#include <libpdb/bit.hpp>
#include <libpdb/error.hpp>
#include <libpdb/pipe.hpp>
#include <libpdb/process.hpp>
#include <libpdb/types.hpp>

#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

namespace pdb {

namespace {

void exitWithPerror(Pipe& channel, std::string const& prefix)
{
    auto message = prefix + ": " + std::strerror(errno);
    channel.write(reinterpret_cast<std::byte*>(message.data()), message.size());
    exit(-1);
}

} // namespace

StopReason::StopReason(int waitStatus)
{
    if(WIFEXITED(waitStatus)) {
        reason = ProcessState::Exited;
        info   = WEXITSTATUS(waitStatus);

    } else if(WIFSIGNALED(waitStatus)) {
        reason = ProcessState::Terminated;
        info   = WTERMSIG(waitStatus);
    } else if(WIFSTOPPED(waitStatus)) {
        reason = ProcessState::Stopped;
        info   = WSTOPSIG(waitStatus);
    }
}

Process::~Process()
{
    if(m_pid != 0) {
        int status;
        if(m_isAttached) {
            if(m_state == ProcessState::Running) {
                kill(m_pid, SIGSTOP);
                waitpid(m_pid, &status, 0);
            }
            ptrace(PTRACE_DETACH, m_pid, nullptr, nullptr);
            kill(m_pid, SIGCONT);
        }

        if(m_terminateOnEnd) {
            kill(m_pid, SIGKILL);
            waitpid(m_pid, &status, 0);
        }
    }
}

std::unique_ptr<Process> Process::launch(std::filesystem::path path, bool debug,
                                         std::optional<int> stdoutReplacement)
{
    Pipe channel(true);
    pid_t pid;
    if((pid = fork()) < 0) {
        Error::sendErrno("fork failed");
    }

    if(pid == 0) {
        personality(ADDR_NO_RANDOMIZE);
        channel.closeRead();
        if(stdoutReplacement) {
            if(dup2(*stdoutReplacement, STDOUT_FILENO) < 0) {
                exitWithPerror(channel, "dup2 failed");
            }
        }
        if(debug && ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
            exitWithPerror(channel, "ptrace TRACEME failed");
        }
        if(execlp(path.c_str(), path.c_str(), nullptr) < 0) {
            exitWithPerror(channel, "execlp failed");
        }
    }

    channel.closeWrite();
    auto data = channel.read();
    channel.closeRead();

    if(data.size() > 0) {
        waitpid(pid, nullptr, 0);
        auto chars = reinterpret_cast<char*>(data.data());
        Error::send(std::string(chars, chars + data.size()));
    }

    std::unique_ptr<Process> proc(new Process(pid, true, debug));

    if(debug) {
        proc->waitOnSignal();
    }

    return proc;
}

std::unique_ptr<Process> Process::attach(pid_t pid)
{
    if(pid == 0) {
        Error::send("Invalid PID");
    }
    if(ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        Error::sendErrno("ptrace ATTACH failed");
    }
    std::unique_ptr<Process> proc(new Process(pid, false, true));
    proc->waitOnSignal();
    return proc;
}

void Process::resume()
{
    auto pc = getProgramCounter();
    if(breakpointSites().enabledStoppointAtAddress(pc)) {
        auto& bp = m_breakpointSites.getByAddress(pc);
        bp.disable();
        if(ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) < 0) {
            Error::sendErrno("Failed to single step");
        }
        int waitStatus;
        if(waitpid(m_pid, &waitStatus, 0) < 0) {
            Error::sendErrno("waitpid failed");
        }
        bp.enable();
    }

    if(ptrace(PTRACE_CONT, m_pid, nullptr, nullptr) < 0) {
        Error::sendErrno("ptrace CONT failed");
    }
    m_state = ProcessState::Running;
}

StopReason Process::waitOnSignal()
{
    int waitStatus = 0;
    int options    = 0;
    if(waitpid(m_pid, &waitStatus, options) < 0) {
        Error::sendErrno("waitpid failed");
    }
    StopReason reason(waitStatus);
    m_state = reason.reason;

    if(m_isAttached && m_state == ProcessState::Stopped) {
        readAllRegisters();
        auto instructionBegin = getProgramCounter();
        instructionBegin -= 1;
        if(reason.info == SIGTRAP
           && breakpointSites().enabledStoppointAtAddress(instructionBegin)) {
            setProgramCounter(instructionBegin);
        }
    }

    return reason;
}

void Process::writeUserArea(size_t offset, uint64_t data)
{
    if(ptrace(PTRACE_POKEUSER, m_pid, offset, data)) {
        Error::sendErrno("Could not write to user data.");
    }
}

void Process::writeFprs(const user_fpregs_struct& fprs)
{
    if(ptrace(PTRACE_SETFPREGS, m_pid, nullptr, &fprs) < 0) {
        Error::sendErrno("Could not write floating point registers");
    }
}

void Process::writeGprs(const user_regs_struct& gprs)
{
    if(ptrace(PTRACE_SETREGS, m_pid, nullptr, &gprs) < 0) {
        Error::sendErrno("Could not write general purpose registers");
    }
}

StopReason Process::stepInstruction()
{
    std::optional<BreakpointSite*> toReenable;
    auto pc = getProgramCounter();
    if(m_breakpointSites.enabledStoppointAtAddress(pc)) {
        auto& bp = m_breakpointSites.getByAddress(pc);
        bp.disable();
        toReenable = &bp;
    }

    if(ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) < 0) {
        Error::sendErrno("Could not single step");
    }
    auto reason = waitOnSignal();

    if(toReenable) {
        toReenable.value()->enable();
    }
    return reason;
}

BreakpointSite& Process::createBreakpointSite(VirtAddr address)
{
    if(m_breakpointSites.containsAddress(address)) {
        Error::send("Breakpoint site already created at address " + std::to_string(address.addr()));
    }
    return m_breakpointSites.push(
        std::unique_ptr<BreakpointSite>(new BreakpointSite(*this, address)));
}

std::vector<std::byte> Process::readMemory(VirtAddr address, size_t amount) const
{
    std::vector<std::byte> ret(amount);

    iovec localDesc{ret.data(), ret.size()};
    std::vector<iovec> remoteDescs;
    while(amount > 0) {
        auto upToNextPage = 0x1000 - (address.addr() & 0xFFF);
        auto chunkSize    = std::min(amount, upToNextPage);
        remoteDescs.push_back({reinterpret_cast<void*>(address.addr()), chunkSize});
        amount -= chunkSize;
        address += chunkSize;
    }
    if(process_vm_readv(m_pid, &localDesc, 1, remoteDescs.data(), remoteDescs.size(), 0) < 0) {
        Error::sendErrno("Could not read process memory");
    }
    return ret;
}

std::vector<std::byte> Process::readMemoryWithoutTraps(VirtAddr address, size_t amount) const
{
    auto memory = readMemory(address, amount);
    auto sites = m_breakpointSites.getInRegion(address, address + amount);
    for(auto site : sites) {
        if(!site->isEnabled()) {
            continue;
        }
        auto offset = site->address() - address.addr();
        memory[offset.addr()] = site->m_savedData;
    }
    return memory;
}

void Process::writeMemory(VirtAddr address, Span<const std::byte> data)
{
    size_t written = 0;
    while(written < data.size()) {
        auto remaining = data.size() - written;
        uint64_t word;
        if(remaining >= 8) {
            word = fromBytes<uint64_t>(data.begin() + written);
        } else {
            auto read     = readMemory(address + written, 8);
            auto wordData = reinterpret_cast<char*>(&word);
            std::memcpy(wordData, data.begin() + written, remaining);
            std::memcpy(wordData + remaining, read.data() + remaining, 8 - remaining);
        }
        if(ptrace(PTRACE_POKEDATA, m_pid, address + written, word) < 0) {
            Error::sendErrno("Failed to write memory");
        }
        written += 8;
    }
}

Process::Process(pid_t pid, bool terminateOnEnd, bool isAttached)
    : m_pid(pid)
    , m_terminateOnEnd(terminateOnEnd)
    , m_isAttached(isAttached)
    , m_registers(new Registers(*this))
{ }

void Process::readAllRegisters()
{
    if(ptrace(PTRACE_GETREGS, m_pid, nullptr, &getRegisters().m_data.regs) < 0) {
        Error::sendErrno("ptrace GETREGS failed. Could not read GPR registers");
    }
    if(ptrace(PTRACE_GETFPREGS, m_pid, nullptr, &getRegisters().m_data.i387) < 0) {
        Error::sendErrno("ptrace GETFPREGS failed. Could not read FPR registers");
    }
    for(int i = 0; i < 8; ++i) {
        auto id   = static_cast<int>(RegisterId::dr0) + i;
        auto info = registerInfoById(static_cast<RegisterId>(id));

        errno        = 0;
        int64_t data = ptrace(PTRACE_PEEKUSER, m_pid, info.offset, nullptr);
        if(errno != 0) {
            Error::sendErrno("Could not read debug register");
        }
        getRegisters().m_data.u_debugreg[i] = data;
    }
}

} // namespace pdb

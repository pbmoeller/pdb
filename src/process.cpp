#include <libpdb/bit.hpp>
#include <libpdb/error.hpp>
#include <libpdb/pipe.hpp>
#include <libpdb/process.hpp>
#include <libpdb/target.hpp>
#include <libpdb/types.hpp>

#include <elf.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>

namespace pdb {

namespace {

void exitWithPerror(Pipe& channel, std::string const& prefix)
{
    auto message = prefix + ": " + std::strerror(errno);
    channel.write(reinterpret_cast<std::byte*>(message.data()), message.size());
    exit(-1);
}

void setPtraceOptions(pid_t pid)
{
    if(ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE) < 0) {
        pdb::Error::sendErrno("Failed to set TRACESYSGOOD and TRACECLONE option");
    }
}

uint64_t encodeHardwareStoppointMode(StoppointMode mode)
{
    switch(mode) {
        case pdb::StoppointMode::Write:
            return 0b01;
        case pdb::StoppointMode::ReadWrite:
            return 0b11;
        case pdb::StoppointMode::Execute:
            return 0b00;
        default:
            Error::send("Invalid stoppoint mode");
    }
}

uint64_t encodeHardwareStoppointSize(size_t size)
{
    switch(size) {
        case 1:
            return 0b00;
        case 2:
            return 0b01;
        case 4:
            return 0b11;
        case 8:
            return 0b10;
        default:
            Error::send("Invalid stoppoint size");
    }
}

int findFreeStoppointRegister(uint64_t controlRegister)
{
    for(auto i = 0; i < 4; ++i) {
        if((controlRegister & (0b11 << (i * 2))) == 0) return i;
    }
    Error::send("No remaining hardware debug registers");
}

} // namespace

StopReason::StopReason(pid_t tid, int waitStatus)
    : tid(tid)
{
    if((waitStatus >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
        trapReason = TrapType::Clone;
    }

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
        if(setpgid(0, 0) < 0) {
            exitWithPerror(channel, "Could not set pgid");
        }
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
        setPtraceOptions(proc->pid());
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
    setPtraceOptions(proc->pid());
    return proc;
}

void Process::resume(std::optional<pid_t> otid)
{
    auto tid = otid.value_or(m_currentThread);
    stepOverBreakpoint(tid);
    sendContinue(tid);
}

StopReason Process::waitOnSignal(pid_t toAwait)
{
    int waitStatus;
    int options    = __WALL;
    pid_t tid;
    if((tid = waitpid(toAwait, &waitStatus, options)) < 0) {
        Error::sendErrno("waitpid failed");
    }

    StopReason reason(tid, waitStatus);
    auto finalReason = handleSignal(reason, true);
    if(!finalReason) {
        resume(tid);
        return waitOnSignal(toAwait);
    }

    reason        = *finalReason;
    auto& thread  = m_threads.at(tid);
    thread.reason = reason;
    thread.state  = reason.reason;

    if(reason.reason == ProcessState::Exited || reason.reason == ProcessState::Terminated) {
        reportThreadLifecycleEvent(reason);
        if(tid == m_pid) {
            m_state = reason.reason;
            return reason;
        } else {
            return waitOnSignal(-1);
        }
    }

    stopRunningThreads();
    reason          = cleanupExitedThreads(tid).value_or(reason);
    m_state         = reason.reason;
    m_currentThread = tid;
    return reason;
}

Registers& Process::getRegisters(std::optional<pid_t> otid)
{
    auto tid = otid.value_or(m_currentThread);
    return m_threads.at(tid).regs;
}

const Registers& Process::getRegisters(std::optional<pid_t> otid) const
{
    return const_cast<Process*>(this)->getRegisters(otid);
}

void Process::writeUserArea(size_t offset, uint64_t data, std::optional<pid_t> otid)
{
    auto tid = otid.value_or(m_currentThread);
    if(ptrace(PTRACE_POKEUSER, tid, offset, data) < 0) {
        Error::sendErrno("Could not write to user data.");
    }
}

void Process::writeFprs(const user_fpregs_struct& fprs, std::optional<pid_t> otid)
{
    auto tid = otid.value_or(m_currentThread);
    if(ptrace(PTRACE_SETFPREGS, tid, nullptr, &fprs) < 0) {
        Error::sendErrno("Could not write floating point registers");
    }
}

void Process::writeGprs(const user_regs_struct& gprs, std::optional<pid_t> otid)
{
    auto tid = otid.value_or(m_currentThread);
    if(ptrace(PTRACE_SETREGS, tid, nullptr, &gprs) < 0) {
        Error::sendErrno("Could not write general purpose registers");
    }
}

VirtAddr Process::getProgramCounter(std::optional<pid_t> otid) const
{
    return VirtAddr{getRegisters(otid).readByIdAs<uint64_t>(RegisterId::rip)};
}

void Process::setProgramCounter(VirtAddr address, std::optional<pid_t> otid)
{
    getRegisters(otid).writeById(RegisterId::rip, address.addr());
}

StopReason Process::stepInstruction(std::optional<pid_t> otid)
{
    auto tid = otid.value_or(m_currentThread);
    std::optional<BreakpointSite*> toReenable;
    auto pc = getProgramCounter(tid);
    if(m_breakpointSites.enabledStoppointAtAddress(pc)) {
        auto& bp = m_breakpointSites.getByAddress(pc);
        bp.disable();
        toReenable = &bp;
    }
    swallowPendingSigstop(tid);
    if(ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) < 0) {
        Error::sendErrno("Could not single step");
    }
    auto reason = waitOnSignal(tid);

    if(toReenable) {
        toReenable.value()->enable();
    }
    return reason;
}

BreakpointSite& Process::createBreakpointSite(VirtAddr address, bool hardware, bool internal)
{
    if(m_breakpointSites.containsAddress(address)) {
        Error::send("Breakpoint site already created at address " + std::to_string(address.addr()));
    }
    return m_breakpointSites.push(
        std::unique_ptr<BreakpointSite>(new BreakpointSite(*this, address, hardware, internal)));
}

BreakpointSite& Process::createBreakpointSite(Breakpoint* parent, BreakpointSite::IdType id,
                                              VirtAddr address, bool hardware, bool internal)
{
    if(m_breakpointSites.containsAddress(address)) {
        Error::send("Breakpoint site already created at address " + std::to_string(address.addr()));
    }
    return m_breakpointSites.push(std::unique_ptr<BreakpointSite>(
        new BreakpointSite(parent, id, *this, address, hardware, internal)));
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
    auto sites  = m_breakpointSites.getInRegion(address, address + amount);
    for(auto site : sites) {
        if(!site->isEnabled() || site->isHardware()) {
            continue;
        }
        auto offset           = site->address() - address.addr();
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

int Process::setHardwareBreakpoint(BreakpointSite::IdType id, VirtAddr address)
{
    return setHardwareStoppoint(address, StoppointMode::Execute, 1);
}

void Process::clearHardwareStoppoint(int index)
{
    auto id = static_cast<int>(RegisterId::dr0) + index;
    getRegisters().writeById(static_cast<RegisterId>(id), 0);

    auto control = getRegisters().readByIdAs<uint64_t>(RegisterId::dr7);

    auto clearMask = (0b11 << (index * 2)) | (0b1111 << (index * 4 + 16));
    auto masked    = control & ~clearMask;
    getRegisters().writeById(RegisterId::dr7, masked);

    for(auto& [tid, _] : m_threads) {
        if(tid == m_currentThread) {
            continue;
        }
        auto& otherRegs = getRegisters(tid);
        otherRegs.writeById(static_cast<RegisterId>(id), 0);
        otherRegs.writeById(RegisterId::dr7, masked);
    }
}

int Process::setWatchpoint(Watchpoint::IdType id, VirtAddr address, StoppointMode mode, size_t size)
{
    return setHardwareStoppoint(address, mode, size);
}

Watchpoint& Process::createWatchpoint(VirtAddr address, StoppointMode mode, size_t size)
{
    if(m_watchpoints.containsAddress(address)) {
        Error::send("Watchpoint already cerated at address " + std::to_string(address.addr()));
    }
    return m_watchpoints.push(
        std::unique_ptr<Watchpoint>(new Watchpoint(*this, address, mode, size)));
}

std::variant<BreakpointSite::IdType, Watchpoint::IdType>
Process::getCurrentHardwareStoppoint(std::optional<pid_t> otid) const
{
    auto& regs  = getRegisters(otid);
    auto status = regs.readByIdAs<uint64_t>(RegisterId::dr6);
    auto index  = __builtin_ctzll(status);

    auto id   = static_cast<int>(RegisterId::dr0) + index;
    auto addr = VirtAddr{regs.readByIdAs<uint64_t>(static_cast<RegisterId>(id))};

    using ret = std::variant<BreakpointSite::IdType, Watchpoint::IdType>;
    if(m_breakpointSites.containsAddress(addr)) {
        auto siteId = m_breakpointSites.getByAddress(addr).id();
        return ret{std::in_place_index<0>, siteId};
    } else {
        auto watchId = m_watchpoints.getByAddress(addr).id();
        return ret{std::in_place_index<1>, watchId};
    }
}

bool Process::shouldResumeFromSyscall(const StopReason& reason)
{
    if(m_syscallCatchPolicy.getMode() == SyscallCatchPolicy::Mode::Some) {
        auto& toCatch = m_syscallCatchPolicy.getToCatch();
        auto found    = std::find(std::begin(toCatch), std::end(toCatch), reason.syscallInfo->id);

        if(found == std::end(toCatch)) {
            return true;
        }
    }
    return false;
}

Process::Process(pid_t pid, bool terminateOnEnd, bool isAttached)
    : m_pid(pid)
    , m_terminateOnEnd(terminateOnEnd)
    , m_isAttached(isAttached)
    , m_currentThread(pid)
{
    populateExistingThreads();
}

void Process::readAllRegisters(pid_t tid)
{
    if(ptrace(PTRACE_GETREGS, tid, nullptr, &getRegisters(tid).m_data.regs) < 0) {
        Error::sendErrno("ptrace GETREGS failed. Could not read GPR registers");
    }
    if(ptrace(PTRACE_GETFPREGS, tid, nullptr, &getRegisters(tid).m_data.i387) < 0) {
        Error::sendErrno("ptrace GETFPREGS failed. Could not read FPR registers");
    }
    for(int i = 0; i < 8; ++i) {
        auto id   = static_cast<int>(RegisterId::dr0) + i;
        auto info = registerInfoById(static_cast<RegisterId>(id));

        errno        = 0;
        int64_t data = ptrace(PTRACE_PEEKUSER, tid, info.offset, nullptr);
        if(errno != 0) {
            Error::sendErrno("Could not read debug register");
        }
        getRegisters(tid).m_data.u_debugreg[i] = data;
    }
}

int Process::setHardwareStoppoint(VirtAddr address, StoppointMode mode, size_t size)
{
    auto& regs   = getRegisters();
    auto control = regs.readByIdAs<uint64_t>(RegisterId::dr7);

    int freeSpace = findFreeStoppointRegister(control);
    auto id       = static_cast<int>(RegisterId::dr0) + freeSpace;
    regs.writeById(static_cast<RegisterId>(id), address.addr());

    auto modeFlag = encodeHardwareStoppointMode(mode);
    auto sizeFlag = encodeHardwareStoppointSize(size);

    auto enableBit = (1 << (freeSpace * 2));
    auto modeBits  = (modeFlag << (freeSpace * 4 + 16));
    auto sizeBits  = (sizeFlag << (freeSpace * 4 + 18));

    auto clearMask = (0b11 << (freeSpace * 2)) | (0b1111 << (freeSpace * 4 + 16));
    auto masked    = control & ~clearMask;

    masked |= enableBit | modeBits | sizeBits;

    regs.writeById(RegisterId::dr7, masked);

    for(auto& [tid, _] : m_threads) {
        if(tid == m_currentThread) {
            continue;
        }
        auto& otherRegs = getRegisters(tid);
        otherRegs.writeById(static_cast<RegisterId>(id), address.addr());
        otherRegs.writeById(RegisterId::dr7, masked);
    }

    return freeSpace;
}

void Process::augmentStopReason(StopReason& reason)
{
    auto tid = reason.tid;
    siginfo_t info;
    if(ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) < 0) {
        Error::sendErrno("Failed to get signal info");
    }

    if(reason.info == (SIGTRAP | 0x80)) {
        auto& sysInfo = reason.syscallInfo.emplace();
        auto& regs    = getRegisters();

        if(m_expectingSyscallExit) {
            sysInfo.entry          = false;
            sysInfo.id             = regs.readByIdAs<uint64_t>(RegisterId::orig_rax);
            sysInfo.ret            = regs.readByIdAs<uint64_t>(RegisterId::rax);
            m_expectingSyscallExit = false;
        } else {
            sysInfo.entry                     = true;
            sysInfo.id                        = regs.readByIdAs<uint64_t>(RegisterId::orig_rax);
            std::array<RegisterId, 6> argRegs = {RegisterId::rdi, RegisterId::rsi, RegisterId::rdx,
                                                 RegisterId::r10, RegisterId::r8,  RegisterId::r9};
            for(auto i = 0; i < 6; ++i) {
                sysInfo.args[i] = regs.readByIdAs<uint64_t>(argRegs[i]);
            }
            m_expectingSyscallExit = true;
        }

        reason.info       = SIGTRAP;
        reason.trapReason = TrapType::Syscall;
        return;
    }

    m_expectingSyscallExit = false;

    reason.trapReason = TrapType::Unknown;
    if(reason.info == SIGTRAP) {
        switch(info.si_code) {
            case TRAP_TRACE:
                reason.trapReason = TrapType::SingleStep;
                break;
            case SI_KERNEL:
                reason.trapReason = TrapType::SoftwareBreak;
                break;
            case TRAP_HWBKPT:
                reason.trapReason = TrapType::HardwareBreak;
                break;
        }
    }
}

std::unordered_map<int, uint64_t> Process::getAuxv() const
{
    auto path = "/proc/" + std::to_string(m_pid) + "/auxv";
    std::ifstream auxv(path);

    std::unordered_map<int, uint64_t> ret;
    uint64_t id;
    uint64_t value;

    auto read = [&](auto& into) { auxv.read(reinterpret_cast<char*>(&into), sizeof(into)); };

    for(read(id); id != AT_NULL; read(id)) {
        read(value);
        ret[id] = value;
    }
    return ret;
}

void Process::populateExistingThreads()
{
    auto path = "/proc/" + std::to_string(m_pid) + "/task";
    for(auto& entry : std::filesystem::directory_iterator(path)) {
        auto tid = std::stoi(entry.path().filename().string());
        m_threads.emplace(tid, ThreadState{tid, Registers(*this, tid)});
    }
}

void Process::stopRunningThreads()
{
    for(auto& [tid, thread] : m_threads) {
        if(thread.state == ProcessState::Running) {
            if(!thread.pendingSigStop) {
                tgkill(m_pid, tid, SIGSTOP);
            }

            int waitStatus;
            waitpid(tid, &waitStatus, 0);

            StopReason threadReason(tid, waitStatus);
            if(threadReason.reason == ProcessState::Stopped) {
                if(threadReason.info != SIGSTOP) {
                    thread.pendingSigStop = true;
                } else if(thread.pendingSigStop) {
                    thread.pendingSigStop = false;
                }
            }

            threadReason             = handleSignal(threadReason, false).value_or(threadReason);
            m_threads.at(tid).reason = threadReason;
            m_threads.at(tid).state  = threadReason.reason;
        }
    }
}

void Process::resumeAllThreads()
{
    for(auto& [tid, _] : m_threads) {
        stepOverBreakpoint(tid);
    }
    for(auto& [tid, _] : m_threads) {
        sendContinue(tid);
    }
}

std::optional<StopReason> Process::cleanupExitedThreads(pid_t mainStopTid)
{
    std::vector<pid_t> toRemove;
    std::optional<StopReason> toReport;
    for(auto& [tid, thread] : m_threads) {
        if(tid != mainStopTid
           && (thread.state == ProcessState::Exited || thread.state == ProcessState::Terminated)) {
            reportThreadLifecycleEvent(thread.reason);
            toRemove.push_back(tid);
            if(tid == m_pid) {
                toReport = thread.reason;
            }
        }
    }

    for(auto tid : toRemove) {
        m_threads.erase(tid);
    }
    return toReport;
}

void Process::reportThreadLifecycleEvent(const StopReason& reason)
{
    if(m_threadLifecycleCallback) {
        m_threadLifecycleCallback(reason);
    }
    if(m_target) {
        m_target->notifyThreadLifecycleEvent(reason);
    }
}

std::optional<StopReason> Process::handleSignal(StopReason reason, bool isMainStop)
{
    auto tid = reason.tid;

    if(reason.trapReason && *reason.trapReason == TrapType::Clone && isMainStop) {
        return std::nullopt;
    }

    if(m_isAttached && reason.reason == ProcessState::Stopped) {
        if(!m_threads.count(tid)) {
            m_threads.emplace(tid, ThreadState{tid, Registers(*this, tid)});
            reportThreadLifecycleEvent(reason);
            if(isMainStop) {
                return std::nullopt;
            }
        }

        if(m_threads.at(tid).pendingSigStop && reason.info == SIGSTOP) {
            m_threads.at(tid).pendingSigStop = false;
            return std::nullopt;
        }

        readAllRegisters(tid);
        augmentStopReason(reason);

        if(reason.info == SIGTRAP) {
            auto instructionBegin = getProgramCounter(tid) - 1;
            if(reason.trapReason == TrapType::SoftwareBreak
               && m_breakpointSites.containsAddress(instructionBegin)
               && m_breakpointSites.getByAddress(instructionBegin).isEnabled()) {
                setProgramCounter(instructionBegin, tid);

                auto& bp = m_breakpointSites.getByAddress(instructionBegin);
                if(bp.m_parent) {
                    bool shouldRestart = bp.m_parent->notifyHit();
                    if(shouldRestart && isMainStop) {
                        return std::nullopt;
                    }
                }
            } else if(reason.trapReason == TrapType::HardwareBreak) {
                auto id = getCurrentHardwareStoppoint(tid);
                if(id.index() == 1) {
                    m_watchpoints.getById(std::get<1>(id)).updateData();
                }
            } else if(reason.trapReason == TrapType::Syscall && isMainStop
                      && shouldResumeFromSyscall(reason)) {
                return std::nullopt;
            }
        }

        if(m_target) {
            m_target->notifyStop(reason);
        }
    }

    return reason;
}

void Process::swallowPendingSigstop(pid_t tid)
{
    if(m_threads.at(tid).pendingSigStop) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        waitpid(tid, nullptr, 0);
        m_threads.at(tid).pendingSigStop = false;
    }
}

void Process::sendContinue(pid_t tid)
{
    auto request = m_syscallCatchPolicy.getMode() == SyscallCatchPolicy::Mode::None
                     ? PTRACE_CONT
                     : PTRACE_SYSCALL;
    if(ptrace(request, tid, nullptr, nullptr) < 0) {
        Error::sendErrno("Could not resume");
    }
    m_threads.at(tid).state = ProcessState::Running;
    m_state                 = ProcessState::Running;
}

void Process::stepOverBreakpoint(pid_t tid)
{
    auto pc = getProgramCounter(tid);
    if(breakpointSites().enabledStoppointAtAddress(pc)) {
        auto& bp = m_breakpointSites.getByAddress(pc);
        bp.disable();
        swallowPendingSigstop(tid);
        if(ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) < 0) {
            Error::sendErrno("Failed to single step");
        }
        int waitStatus;
        if(waitpid(tid, &waitStatus, 0) < 0) {
            Error::sendErrno("waitpid failed");
        }
        bp.enable();
    }
}

} // namespace pdb

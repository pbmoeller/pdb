#include <libpdb/error.hpp>
#include <libpdb/pipe.hpp>
#include <libpdb/process.hpp>

#include <sys/ptrace.h>
#include <sys/types.h>
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

std::unique_ptr<Process> Process::launch(std::filesystem::path path, bool debug)
{
    Pipe channel(true);
    pid_t pid;
    if((pid = fork()) < 0) {
        Error::sendErrno("fork failed");
    }

    if(pid == 0) {
        channel.closeRead();
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
    if(ptrace(PTRACE_CONT, m_pid, nullptr, nullptr)) {
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
    return reason;
}

Process::Process(pid_t pid, bool terminateOnEnd, bool isAttached)
    : m_pid(pid)
    , m_terminateOnEnd(terminateOnEnd)
    , m_isAttached(isAttached)
{ }

} // namespace pdb

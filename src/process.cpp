#include <libpdb/error.hpp>
#include <libpdb/process.hpp>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace pdb {

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
        if(m_state == ProcessState::Running) {
            kill(m_pid, SIGSTOP);
            waitpid(m_pid, &status, 0);
        }
        ptrace(PTRACE_DETACH, m_pid, nullptr, nullptr);
        kill(m_pid, SIGCONT);
        if(m_terminateOnEnd) {
            kill(m_pid, SIGKILL);
            waitpid(m_pid, &status, 0);
        }
    }
}

std::unique_ptr<Process> Process::launch(std::filesystem::path path)
{
    pid_t pid;
    if((pid = fork()) < 0) {
        Error::sendErrno("fork failed");
    }

    if(pid == 0) {
        if(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
            Error::sendErrno("ptrace TRACEME failed");
        }
        if(execlp(path.c_str(), path.c_str(), nullptr) < 0) {
            Error::sendErrno("execlp failed");
        }
    }

    std::unique_ptr<Process> proc(new Process(pid, true));
    proc->waitOnSignal();

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
    std::unique_ptr<Process> proc(new Process(pid, false));
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

StopReason Process::waitOnSignal() {
    int waitStatus = 0;
    int options    = 0;
    if(waitpid(m_pid, &waitStatus, options) < 0) {
        Error::sendErrno("waitpid failed");
    }
    StopReason reason(waitStatus);
    m_state = reason.reason;
    return reason;
}

Process::Process(pid_t pid, bool terminateOnEnd)
    : m_pid(pid)
    , m_terminateOnEnd(terminateOnEnd)
{ }

} // namespace pdb

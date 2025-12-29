#ifndef PDB_PROCESS_HPP
#define PDB_PROCESS_HPP

#include <sys/types.h>

#include <filesystem>
#include <memory>

namespace pdb {

enum class ProcessState
{
    Stopped,
    Running,
    Exited,
    Terminated
};

struct StopReason
{
    StopReason(int waitStatus);

    ProcessState reason;
    uint8_t info;
};

class Process
{
public:
    Process()                          = delete;
    Process(const Process&)            = delete;
    Process& operator=(const Process&) = delete;
    ~Process();

    static std::unique_ptr<Process> launch(std::filesystem::path path);
    static std::unique_ptr<Process> attach(pid_t pid);

    void resume();
    StopReason waitOnSignal();

    pid_t pid() const { return m_pid; }
    ProcessState state() const { return m_state; }

private:
    Process(pid_t pid, bool terminateOnEnd);

private:
    pid_t m_pid{0};
    bool m_terminateOnEnd{true};
    ProcessState m_state{ProcessState::Stopped};
};

} // namespace pdb

#endif // PDB_PROCESS_HPP

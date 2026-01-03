#ifndef LIBPDB_PROCESS_HPP
#define LIBPDB_PROCESS_HPP

#include <libpdb/breakpoint_site.hpp>
#include <libpdb/registers.hpp>
#include <libpdb/stoppoint_collection.hpp>
#include <libpdb/types.hpp>

#include <sys/types.h>

#include <filesystem>
#include <memory>
#include <optional>

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

    static std::unique_ptr<Process> launch(std::filesystem::path path, bool debug = true,
                                           std::optional<int> stdoutReplacement = std::nullopt);
    static std::unique_ptr<Process> attach(pid_t pid);

    void resume();
    StopReason waitOnSignal();

    pid_t pid() const { return m_pid; }
    ProcessState state() const { return m_state; }

    Registers& getRegisters() { return *m_registers; }
    const Registers& getRegisters() const { return *m_registers; }

    void writeUserArea(size_t offset, uint64_t data);

    void writeFprs(const user_fpregs_struct& fprs);
    void writeGprs(const user_regs_struct& gprs);

    VirtAddr getProgramCounter() const
    {
        return VirtAddr{getRegisters().readByIdAs<uint64_t>(RegisterId::rip)};
    }
    void setProgramCounter(VirtAddr address) {
        getRegisters().writeById(RegisterId::rip, address.addr());
    }

    BreakpointSite& createBreakpointSite(VirtAddr address);

    StoppointCollection<BreakpointSite>& breakpointSites() { return m_breakpointSites; }
    const StoppointCollection<BreakpointSite>& breakpointSites() const { return m_breakpointSites; }

private:
    Process(pid_t pid, bool terminateOnEnd, bool isAttached);

    void readAllRegisters();

private:
    pid_t m_pid{0};
    bool m_terminateOnEnd{true};
    ProcessState m_state{ProcessState::Stopped};
    bool m_isAttached{true};
    std::unique_ptr<Registers> m_registers;
    StoppointCollection<BreakpointSite> m_breakpointSites;
};

} // namespace pdb

#endif // LIBPDB_PROCESS_HPP

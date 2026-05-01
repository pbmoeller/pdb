#ifndef LIBPDB_PROCESS_HPP
#define LIBPDB_PROCESS_HPP

#include <libpdb/bit.hpp>
#include <libpdb/breakpoint_site.hpp>
#include <libpdb/registers.hpp>
#include <libpdb/stoppoint_collection.hpp>
#include <libpdb/types.hpp>
#include <libpdb/watchpoint.hpp>

#include <sys/types.h>

#include <csignal>
#include <filesystem>
#include <memory>
#include <optional>
#include <unordered_map>

namespace pdb {

enum class ProcessState
{
    Stopped,
    Running,
    Exited,
    Terminated
};

enum class TrapType
{
    SingleStep,
    SoftwareBreak,
    HardwareBreak,
    Syscall,
    Unknown,
};

struct SyscallInformation
{
    uint16_t id;
    bool entry;
    union {
        std::array<uint64_t, 6> args;
        int64_t ret;
    };
};

struct StopReason
{
    StopReason() = default;
    StopReason(int waitStatus);
    StopReason(ProcessState reason, uint8_t info, std::optional<TrapType> trapReason = std::nullopt,
               std::optional<SyscallInformation> syscallInfo = std::nullopt)
        : reason(reason)
        , info(info)
        , trapReason(trapReason)
        , syscallInfo(syscallInfo)
    { }

    bool isStep() const
    {
        return reason == ProcessState::Stopped && info == SIGTRAP
            && trapReason == TrapType::SingleStep;
    }

    bool isBreakpoint() const
    {
        return reason == ProcessState::Stopped && info == SIGTRAP
            && (trapReason == TrapType::SoftwareBreak || trapReason == TrapType::HardwareBreak);
    }

    ProcessState reason;
    uint8_t info;
    std::optional<TrapType> trapReason;
    std::optional<SyscallInformation> syscallInfo;
};

class SyscallCatchPolicy
{
public:
    enum Mode
    {
        None,
        Some,
        All,
    };

    static SyscallCatchPolicy catchAll() { return {Mode::All, {}}; }
    static SyscallCatchPolicy catchNone() { return {Mode::None, {}}; }
    static SyscallCatchPolicy catchSome(std::vector<int> toCatch)
    {
        return {Mode::Some, std::move(toCatch)};
    }

    Mode getMode() const { return m_mode; }
    const std::vector<int>& getToCatch() const { return m_toCatch; }

private:
    SyscallCatchPolicy(Mode mode, std::vector<int> toCatch)
        : m_mode(mode)
        , m_toCatch(toCatch)
    { }

    Mode m_mode{Mode::None};
    std::vector<int> m_toCatch;
};

class Target;

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
    void setProgramCounter(VirtAddr address)
    {
        getRegisters().writeById(RegisterId::rip, address.addr());
    }

    StopReason stepInstruction();

    BreakpointSite& createBreakpointSite(VirtAddr address, bool hardware = false,
                                         bool internal = false);
    BreakpointSite& createBreakpointSite(Breakpoint* parent, BreakpointSite::IdType idType,
                                         VirtAddr address, bool hardware = false,
                                         bool internal = false);

    StoppointCollection<BreakpointSite>& breakpointSites() { return m_breakpointSites; }
    const StoppointCollection<BreakpointSite>& breakpointSites() const { return m_breakpointSites; }

    std::vector<std::byte> readMemory(VirtAddr address, size_t amount) const;
    std::vector<std::byte> readMemoryWithoutTraps(VirtAddr address, size_t amount) const;
    void writeMemory(VirtAddr address, Span<const std::byte> data);

    template<typename T>
    T readMemoryAs(VirtAddr address) const
    {
        auto data = readMemory(address, sizeof(T));
        return fromBytes<T>(data.data());
    }

    int setHardwareBreakpoint(BreakpointSite::IdType id, VirtAddr address);
    void clearHardwareStoppoint(int index);
    int setWatchpoint(Watchpoint::IdType id, VirtAddr address, StoppointMode mode, size_t size);

    Watchpoint& createWatchpoint(VirtAddr address, StoppointMode mode, size_t size);

    StoppointCollection<Watchpoint>& watchpoints() { return m_watchpoints; }
    const StoppointCollection<Watchpoint>& watchpoints() const { return m_watchpoints; }

    std::variant<BreakpointSite::IdType, Watchpoint::IdType> getCurrentHardwareStoppoint() const;

    void setSyscallCatchPolicy(SyscallCatchPolicy info) { m_syscallCatchPolicy = std::move(info); }

    StopReason maybeResumeFromSyscall(const StopReason& reason);

    std::unordered_map<int, uint64_t> getAuxv() const;

    void setTarget(Target* target) { m_target = target; }

private:
    Process(pid_t pid, bool terminateOnEnd, bool isAttached);

    void readAllRegisters();

    int setHardwareStoppoint(VirtAddr address, StoppointMode mode, size_t size);

    void augmentStopReason(StopReason& reason);

private:
    pid_t m_pid{0};
    bool m_terminateOnEnd{true};
    ProcessState m_state{ProcessState::Stopped};
    bool m_isAttached{true};
    std::unique_ptr<Registers> m_registers;
    StoppointCollection<BreakpointSite> m_breakpointSites;
    StoppointCollection<Watchpoint> m_watchpoints;
    SyscallCatchPolicy m_syscallCatchPolicy{SyscallCatchPolicy::catchNone()};
    bool m_expectingSyscallExit{false};
    Target* m_target{nullptr};
};

} // namespace pdb

#endif // LIBPDB_PROCESS_HPP

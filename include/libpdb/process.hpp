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
#include <functional>
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
    Clone,
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
    StopReason(pid_t tid, int waitStatus);
    StopReason(pid_t tid, ProcessState reason, uint8_t info,
               std::optional<TrapType> trapReason            = std::nullopt,
               std::optional<SyscallInformation> syscallInfo = std::nullopt)
        : reason(reason)
        , info(info)
        , trapReason(trapReason)
        , syscallInfo(syscallInfo)
        , tid(tid)
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
    pid_t tid;
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

struct ThreadState
{
    pid_t tid;
    Registers regs;
    StopReason reason;
    ProcessState state{ProcessState::Stopped};
    bool pendingSigStop{false};
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

    void resume(std::optional<pid_t> otid = std::nullopt);
    StopReason waitOnSignal(pid_t toAwait = -1);

    pid_t pid() const { return m_pid; }
    ProcessState state() const { return m_state; }

    Registers& getRegisters(std::optional<pid_t> otid = std::nullopt);
    const Registers& getRegisters(std::optional<pid_t> otid = std::nullopt) const;

    void writeUserArea(size_t offset, uint64_t data, std::optional<pid_t> otid = std::nullopt);
    void writeFprs(const user_fpregs_struct& fprs, std::optional<pid_t> otid = std::nullopt);
    void writeGprs(const user_regs_struct& gprs, std::optional<pid_t> otid = std::nullopt);

    VirtAddr getProgramCounter(std::optional<pid_t> otid = std::nullopt) const;
    void setProgramCounter(VirtAddr address, std::optional<pid_t> otid = std::nullopt);

    StopReason stepInstruction(std::optional<pid_t> otid = std::nullopt);

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

    std::variant<BreakpointSite::IdType, Watchpoint::IdType>
    getCurrentHardwareStoppoint(std::optional<pid_t> otid = std::nullopt) const;

    void setSyscallCatchPolicy(SyscallCatchPolicy info) { m_syscallCatchPolicy = std::move(info); }

    bool shouldResumeFromSyscall(const StopReason& reason);

    std::unordered_map<int, uint64_t> getAuxv() const;

    void setTarget(Target* target) { m_target = target; }

    void setCurrentThread(pid_t tid) { m_currentThread = tid; }
    pid_t currentThread() const { return m_currentThread; }

    std::unordered_map<pid_t, ThreadState>& threadStates() { return m_threads; }
    const std::unordered_map<pid_t, ThreadState>& threadStates() const { return m_threads; }

    void populateExistingThreads();

    void stopRunningThreads();
    void resumeAllThreads();

    std::optional<StopReason> cleanupExitedThreads(pid_t mainStopTid);
    void reportThreadLifecycleEvent(const StopReason& reason);

    std::optional<StopReason> handleSignal(StopReason reason, bool isMainStop);

    void installThreadLifecycleCallback(std::function<void(const StopReason&)> callback) {
        m_threadLifecycleCallback = std::move(callback);
    }

    std::string readString(VirtAddr address) const;

private:
    Process(pid_t pid, bool terminateOnEnd, bool isAttached);

    void readAllRegisters(pid_t tid);

    int setHardwareStoppoint(VirtAddr address, StoppointMode mode, size_t size);

    void augmentStopReason(StopReason& reason);

    void swallowPendingSigstop(pid_t tid);
    void sendContinue(pid_t tid);
    void stepOverBreakpoint(pid_t tid);

private:
    pid_t m_pid{0};
    bool m_terminateOnEnd{true};
    ProcessState m_state{ProcessState::Stopped};
    bool m_isAttached{true};
    StoppointCollection<BreakpointSite> m_breakpointSites;
    StoppointCollection<Watchpoint> m_watchpoints;
    SyscallCatchPolicy m_syscallCatchPolicy{SyscallCatchPolicy::catchNone()};
    bool m_expectingSyscallExit{false};
    Target* m_target{nullptr};
    pid_t m_currentThread{0};
    std::unordered_map<pid_t, ThreadState> m_threads;
    std::function<void(const StopReason&)> m_threadLifecycleCallback;
};

} // namespace pdb

#endif // LIBPDB_PROCESS_HPP

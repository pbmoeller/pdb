#ifndef LIBPDB_TARGET_HPP
#define LIBPDB_TARGET_HPP

#include <libpdb/breakpoint.hpp>
#include <libpdb/elf.hpp>
#include <libpdb/process.hpp>
#include <libpdb/stack.hpp>

#include <link.h>

#include <filesystem>
#include <memory>

namespace pdb {

class Target
{
public:
    Target()                         = delete;
    Target(const Target&)            = delete;
    Target& operator=(const Target&) = delete;

    static std::unique_ptr<Target> launch(std::filesystem::path path,
                                          std::optional<int> stdoutReplacement = std::nullopt);
    static std::unique_ptr<Target> attach(pid_t pid);

    Process& getProcess() { return *m_process; }
    const Process& getProcess() const { return *m_process; }
    Stack& getStack() { return m_stack; }
    const Stack& getStack() const { return m_stack; }

    void notifyStop(const StopReason& reason);

    FileAddr getPcFileAddress() const;

    StopReason stepIn();
    StopReason stepOver();
    StopReason stepOut();

    LineTable::Iterator lineEntryAtPc() const;
    StopReason runUntilAddress(VirtAddr address);

    struct FindFunctionResult
    {
        std::vector<Die> dwarfFunctions;
        std::vector<std::pair<const Elf*, const Elf64_Sym*>> elfFunctions;
    };
    FindFunctionResult findFunctions(std::string name) const;

    Breakpoint& createAddressBreakpoint(VirtAddr address, bool hardware = false,
                                        bool internal = false);
    Breakpoint& createFunctionBreakpoint(std::string functionName, bool hardware = false,
                                         bool internal = false);
    Breakpoint& createLineBreakpoint(std::filesystem::path file, size_t line, bool hardware = false,
                                     bool internal = false);

    StoppointCollection<Breakpoint>& breakpoints() { return m_breakpoints; }
    const StoppointCollection<Breakpoint>& breakpoints() const { return m_breakpoints; }

    std::string functionNameAtAddress(VirtAddr address) const;

    std::optional<r_debug> readDynamicLinkerRendezvous() const;

    ElfCollection& getElves() { return m_elves; }
    const ElfCollection& getElves() const { return m_elves; }
    Elf& getMainElf() { return *m_mainElf; }
    const Elf& getMainElf() const { return *m_mainElf; }

    std::vector<LineTable::Iterator> getLineEntriesByLine(std::filesystem::path path,
                                                          std::size_t line) const;

private:
    Target(std::unique_ptr<Process> proc, std::unique_ptr<Elf> obj)
        : m_process(std::move(proc))
        , m_stack(this)
        , m_mainElf(obj.get())
    {
        m_elves.push(std::move(obj));
    }

    void resolveDynamicLinkerRendezvous();
    void reloadDynamicLibraries();

    std::unique_ptr<Process> m_process;
    ElfCollection m_elves;
    Elf* m_mainElf;
    Stack m_stack;
    StoppointCollection<Breakpoint> m_breakpoints;
    VirtAddr m_dynamicLinkerRendezvousAddress;
};

} // namespace pdb

#endif // LIBPDB_TARGET_HPP

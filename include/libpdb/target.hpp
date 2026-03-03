#ifndef LIBPDB_TARGET_HPP
#define LIBPDB_TARGET_HPP

#include <libpdb/elf.hpp>
#include <libpdb/process.hpp>

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
    Elf& getElf() { return *m_elf; }
    const Elf& getElf() const { return *m_elf; }

private:
    Target(std::unique_ptr<Process> proc, std::unique_ptr<Elf> obj)
        : m_process(std::move(proc))
        , m_elf(std::move(obj))
    { }

    std::unique_ptr<Process> m_process;
    std::unique_ptr<Elf> m_elf;
};

} // namespace pdb

#endif // LIBPDB_TARGET_HPP

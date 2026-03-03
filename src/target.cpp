#include <libpdb/target.hpp>
#include <libpdb/types.hpp>

namespace pdb {

namespace {

std::unique_ptr<Elf> createLoadedElf(const Process& proc, const std::filesystem::path& path)
{
    auto auxv = proc.getAuxv();
    auto obj  = std::make_unique<Elf>(path);
    obj->notifyLoaded(VirtAddr{auxv[AT_ENTRY] - obj->header().e_entry});
    return obj;
}

} // namespace

std::unique_ptr<Target> Target::launch(std::filesystem::path path,
                                       std::optional<int> stdoutReplacement)
{
    auto proc = Process::launch(path, true, stdoutReplacement);
    auto obj  = createLoadedElf(*proc, path);
    return std::unique_ptr<Target>(new Target(std::move(proc), std::move(obj)));
}

std::unique_ptr<Target> Target::attach(pid_t pid)
{
    auto elfPath = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto proc    = Process::attach(pid);
    auto obj     = createLoadedElf(*proc, elfPath);
    return std::unique_ptr<Target>(new Target(std::move(proc), std::move(obj)));
}

} // namespace pdb

#include <libpdb/error.hpp>
#include <libpdb/syscalls.hpp>

#include <unordered_map>

namespace pdb {

namespace {

const std::unordered_map<std::string_view, int> g_syscallNameMap = {
#define DEFINE_SYSCALL(name, id) {#name, id},
#include "include/syscalls.inc"
#undef DEFINE_SYSCALL
};

} // namespace

std::string_view syscallIdToName(int id)
{
    switch(id) {
#define DEFINE_SYSCALL(name, id)                                                                   \
    case id:                                                                                       \
        return #name;
#include "include/syscalls.inc"
#undef DEFINE_SYSCALL
        default:
            pdb::Error::send("No such syscall");
    }
}

int syscallNameToId(std::string_view name) {
    if(g_syscallNameMap.count(name) != 1) {
        pdb::Error::send("No such syscall");
    }
    return g_syscallNameMap.at(name);
}

} // namespace pdb

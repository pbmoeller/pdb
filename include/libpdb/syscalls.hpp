#ifndef LIBPDB_SYSCALLS_HPP
#define LIBPDB_SYSCALLS_HPP

#include <string_view>

namespace pdb {

std::string_view syscallIdToName(int id);
int syscallNameToId(std::string_view name);

} // namespace pdb

#endif // LIBPDB_SYSCALLS_HPP

#ifndef LIBPDB_TYPES_HPP
#define LIBPDB_TYPES_HPP

#include <array>
#include <cstddef>

namespace pdb {

using byte64  = std::array<std::byte, 8>;
using byte128 = std::array<std::byte, 16>;

} // namespace pdb

#endif // LIBPDB_TYPES_HPP

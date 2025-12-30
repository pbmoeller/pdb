#ifndef LIBPDB_REGISTER_INFO_HPP
#define LIBPDB_REGISTER_INFO_HPP

#include <libpdb/error.hpp>

#include <sys/user.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace pdb {

enum class RegisterType
{
    GPR,     // General Purpose Register
    SUB_GPR, // Sub General Purpose Register
    FPR,     // Floating Point Register
    DR,      // Debug Register
};

enum class RegisterFormat
{
    UINT,
    DOUBLE_FLOAT,
    LONG_DOUBLE,
    VECTOR
};

enum class RegisterId
{
#define DEFINE_REGISTER(name, dwarf_id, size, offset, type, format) name
#include <libpdb/detail/registers.inc>
#undef DEFINE_REGISTER
};

struct RegisterInfo
{
    RegisterId id;
    std::string_view name;
    int32_t dwarfId;
    size_t size;
    size_t offset;
    RegisterType type;
    RegisterFormat format;
};

inline constexpr const RegisterInfo g_registerInfos[] = {
#define DEFINE_REGISTER(name, dwarf_id, size, offset, type, format)                                \
    {RegisterId::name, #name, dwarf_id, size, offset, type, format}
#include <libpdb/detail/registers.inc>
#undef DEFINE_REGISTER
};

template<typename T>
const RegisterInfo& registerInfoBy(T t)
{
    auto it = std::find_if(std::begin(g_registerInfos), std::end(g_registerInfos), t);
    if(it == std::end(g_registerInfos)) {
        Error::send("RegisterInfo not found");
    }
    return *it;
}

inline const RegisterInfo& registerInfoById(RegisterId id)
{
    return registerInfoBy([id](auto &info) { return info.id == id; });
}
inline const RegisterInfo& registerInfoByName(std::string_view name)
{
    return registerInfoBy([name](auto &info) { return info.name == name; });
}
inline const RegisterInfo& registerInfoByDwarf(int32_t dwarfId)
{
    return registerInfoBy([dwarfId](auto &info) { return info.dwarfId == dwarfId; });
}

} // namespace pdb

#endif // LIBPDB_REGISTER_INFO_HPP

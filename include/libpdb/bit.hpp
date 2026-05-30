#ifndef LIBPDB_BIT_HPP
#define LIBPDB_BIT_HPP

#include <libpdb/types.hpp>

#include <cstring>
#include <string_view>
#include <vector>

namespace pdb {

template<typename To>
To fromBytes(const std::byte* bytes)
{
    To ret;
    std::memcpy(&ret, bytes, sizeof(To));
    return ret;
}

template<typename From>
std::byte* asBytes(From& from)
{
    return reinterpret_cast<std::byte*>(&from);
}

template<typename From>
const std::byte* asBytes(const From& from)
{
    return reinterpret_cast<const std::byte*>(&from);
}

template<typename From>
byte64 toByte64(From src)
{
    byte64 ret{};
    std::memcpy(&ret, &src, sizeof(From));
    return ret;
}

template<typename From>
byte128 toByte128(From src)
{
    byte128 ret{};
    std::memcpy(&ret, &src, sizeof(From));
    return ret;
}

inline std::string_view toStringView(const std::byte* data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

inline std::string_view toStringView(const std::vector<std::byte>& data)
{
    return toStringView(data.data(), data.size());
}

inline void memcpyBits(uint8_t* dest, uint32_t destBit, const uint8_t* src, uint32_t srcBit,
                       uint32_t nBits)
{
    for(; nBits; --nBits, ++srcBit, ++destBit) {
        uint8_t destMask = 1 << (destBit % 8);
        dest[destBit / 8] &= ~destMask;
        auto srcMask                = 1 << (srcBit % 8);
        auto correspondingSrcBitSet = src[srcBit / 8] & srcMask;
        if(correspondingSrcBitSet) {
            dest[destBit / 8] |= destMask;
        }
    }
}

} // namespace pdb

#endif // LIBPDB_BIT_HPP

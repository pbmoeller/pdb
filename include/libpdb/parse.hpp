#ifndef PDB_PARSE_HPP
#define PDB_PARSE_HPP

#include <libpdb/error.hpp>

#include <array>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>

namespace pdb {

template<typename T>
std::optional<T> toIntegral(std::string_view sv, int base = 10)
{
    auto begin = sv.begin();
    if(base == 16 && sv.size() > 1 && begin[0] == '0' and begin[1] == 'x') {
        begin += 2;
    }

    T ret;
    auto result = std::from_chars(begin, sv.end(), ret, base);

    if(result.ptr != sv.end()) {
        return std::nullopt;
    }
    return ret;
}

template<>
inline std::optional<std::byte> toIntegral(std::string_view sv, int base)
{
    auto uint8 = toIntegral<uint8_t>(sv, base);
    if(uint8) {
        return static_cast<std::byte>(*uint8);
    }
    return std::nullopt;
}

template<typename T>
std::optional<T> toFloat(std::string_view sv)
{
    T ret;
    auto result = std::from_chars(sv.begin(), sv.end(), ret);

    if(result.ptr != sv.end()) {
        return std::nullopt;
    }
    return ret;
}

template<size_t N>
auto parseVector(std::string_view sv)
{
    auto invalid = [] { pdb::Error::send("Invalid format"); };

    std::array<std::byte, N> bytes;
    const char* c = sv.data();

    if(*c++ != '[') {
        invalid();
    }
    for(auto i = 0; i < N - 1; ++i) {
        bytes[i] = toIntegral<std::byte>({c, 4}, 16).value();
        c += 4;
        if(*c++ != ',') {
            invalid();
        }
    }

    bytes[N - 1] = toIntegral<std::byte>({c, 4}, 16).value();
    c += 4;

    if(*c++ != ']') {
        invalid();
    }
    if(c != sv.end()) {
        invalid();
    }
    return bytes;
}

} // namespace pdb

#endif // PDB_PARSE_HPP

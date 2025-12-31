#ifndef LIBPDB_TYPES_HPP
#define LIBPDB_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace pdb {

using byte64  = std::array<std::byte, 8>;
using byte128 = std::array<std::byte, 16>;

class VirtAddr
{
public:
    VirtAddr() = default;
    explicit VirtAddr(uint64_t addr)
        : m_addr(addr)
    { }

    operator uint64_t() const { return m_addr; }

    uint64_t addr() const { return m_addr; }

    VirtAddr operator+(int64_t offset) const { return VirtAddr(m_addr + offset); }
    VirtAddr operator-(int64_t offset) const { return VirtAddr(m_addr - offset); }
    VirtAddr operator+=(int64_t offset)
    {
        m_addr += offset;
        return *this;
    }
    VirtAddr operator-(int64_t offset)
    {
        m_addr -= offset;
        return *this;
    }
    bool operator==(const VirtAddr& other) const { return m_addr == other.m_addr; }
    bool operator!=(const VirtAddr& other) const { return m_addr != other.m_addr; }
    bool operator<(const VirtAddr& other) const { return m_addr < other.m_addr; }
    bool operator<=(const VirtAddr& other) const { return m_addr <= other.m_addr; }
    bool operator>(const VirtAddr& other) const { return m_addr > other.m_addr; }
    bool operator>=(const VirtAddr& other) const { return m_addr >= other.m_addr; }

private:
    uint64_t m_addr{0};
};

} // namespace pdb

#endif // LIBPDB_TYPES_HPP

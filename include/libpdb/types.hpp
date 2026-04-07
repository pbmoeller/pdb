#ifndef LIBPDB_TYPES_HPP
#define LIBPDB_TYPES_HPP

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pdb {

using byte64  = std::array<std::byte, 8>;
using byte128 = std::array<std::byte, 16>;

enum class StoppointMode
{
    Write,
    ReadWrite,
    Execute
};

class Elf;
class FileAddr;

class VirtAddr
{
public:
    VirtAddr() = default;
    explicit VirtAddr(uint64_t addr)
        : m_addr(addr)
    { }

    uint64_t addr() const { return m_addr; }

    VirtAddr operator+(int64_t offset) const { return VirtAddr(m_addr + offset); }
    VirtAddr operator-(int64_t offset) const { return VirtAddr(m_addr - offset); }
    VirtAddr& operator+=(int64_t offset)
    {
        m_addr += offset;
        return *this;
    }
    VirtAddr& operator-=(int64_t offset)
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

    FileAddr toFileAddr(const Elf& obj) const;

private:
    uint64_t m_addr{0};
};

class FileAddr
{
public:
    FileAddr() = default;
    FileAddr(const Elf& obj, uint64_t addr)
        : m_elf(&obj)
        , m_addr(addr)
    { }

    uint64_t addr() const { return m_addr; }
    const Elf* elfFile() const { return m_elf; }

    FileAddr operator+(int64_t offset) const { return FileAddr(*m_elf, m_addr + offset); }
    FileAddr operator-(int64_t offset) const { return FileAddr(*m_elf, m_addr - offset); }
    FileAddr& operator+=(int64_t offset)
    {
        m_addr += offset;
        return *this;
    }
    FileAddr& operator-=(int64_t offset)
    {
        m_addr -= offset;
        return *this;
    }
    bool operator==(const FileAddr& other) const
    {
        return m_addr == other.m_addr && m_elf == other.m_elf;
    }
    bool operator!=(const FileAddr& other) const { return !(*this == other); }
    bool operator<(const FileAddr& other) const
    {
        assert(m_elf == other.m_elf);
        return m_addr < other.m_addr;
    }
    bool operator<=(const FileAddr& other) const
    {
        assert(m_elf == other.m_elf);
        return m_addr <= other.m_addr;
    }
    bool operator>(const FileAddr& other) const
    {
        assert(m_elf == other.m_elf);
        return m_addr > other.m_addr;
    }
    bool operator>=(const FileAddr& other) const
    {
        assert(m_elf == other.m_elf);
        return m_addr >= other.m_addr;
    }

    VirtAddr toVirtAddr() const;

private:
    const Elf* m_elf{nullptr};
    uint64_t m_addr{0};
};

class FileOffset
{
public:
    FileOffset() = default;
    FileOffset(const Elf &obj, uint64_t off)
        : m_elf(&obj), m_offset(off) {
    }
    uint64_t offset() const {
        return m_offset;
    }
    const Elf* elfFile() const {
        return m_elf;
    }

private:
    const Elf *m_elf{nullptr};
    uint64_t m_offset{0};
};

template<typename T>
class Span
{
public:
    Span() = default;
    Span(T* data, size_t size)
        : m_data{data}
        , m_size{size}
    { }
    Span(T* data, T* end)
        : m_data{data}
        , m_size(end - data)
    { }
    template<typename U>
    Span(const std::vector<U>& vec)
        : m_data{vec.data()}
        , m_size{vec.size()}
    { }

    T* begin() const { return m_data; }
    T* end() const { return m_data + m_size; }
    size_t size() const { return m_size; }
    T& operator[](size_t n) { return *(m_data + n); }

private:
    T* m_data{nullptr};
    size_t m_size{0};
};

} // namespace pdb

#endif // LIBPDB_TYPES_HPP

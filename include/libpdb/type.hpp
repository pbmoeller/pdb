#ifndef LIBPDB_TYPE_HPP
#define LIBPDB_TYPE_HPP

#include <libpdb/dwarf.hpp>

#include <optional>
#include <string_view>
#include <vector>

namespace pdb {

class Process;

class Type
{
public:
    Type(Die die)
        : m_die(std::move(die))
    { }
    Die getDie() const { return m_die; }
    size_t byteSize() const;
    bool isCharType() const;

    template<int... Tags>
    Type strip() const
    {
        auto ret = *this;
        auto tag = ret.getDie().abbrevEntry()->tag;
        while(((tag == Tags) || ...)) {
            ret = ret.getDie()[DW_AT_type].asType().getDie();
            tag = ret.getDie().abbrevEntry()->tag;
        }
        return ret;
    }
    Type stripCvTypedef() const
    {
        return strip<DW_TAG_const_type, DW_TAG_volatile_type, DW_TAG_typedef>();
    }
    Type stripCvRefTypedef() const
    {
        return strip<DW_TAG_const_type, DW_TAG_volatile_type, DW_TAG_typedef, DW_TAG_reference_type,
                     DW_TAG_rvalue_reference_type>();
    }
    Type stripAll() const
    {
        return strip<DW_TAG_const_type, DW_TAG_volatile_type, DW_TAG_typedef, DW_TAG_reference_type,
                     DW_TAG_rvalue_reference_type, DW_TAG_pointer_type>();
    }

private:
    size_t computeByteSize() const;

private:
    Die m_die;
    mutable std::optional<size_t> m_byteSize;
};

class TypedData
{
public:
    TypedData(std::vector<std::byte> data, Type valueType,
              std::optional<VirtAddr> address = std::nullopt)
        : m_data(std::move(data))
        , m_type(valueType)
        , m_address(address)
    { }

    const std::vector<std::byte>& data() const { return m_data; }
    const std::byte* dataPtr() const { return m_data.data(); }
    const Type& valueType() const { return m_type; }
    std::optional<VirtAddr> address() const { return m_address; }

    TypedData fixupBitfield(const Process& proc, const Die& memberDie) const;
    std::string visualize(const Process& proc, int depth = 0) const;

    TypedData derefPointer(const Process &proc) const;
    TypedData readMember(const Process & proc, std::string_view memberName) const;
    TypedData index(const Process &proc, size_t index);

private:
    std::vector<std::byte> m_data;
    Type m_type;
    std::optional<VirtAddr> m_address;
};

} // namespace pdb

#endif // LIBPDB_TYPE_HPP

#include <libpdb/bit.hpp>
#include <libpdb/process.hpp>
#include <libpdb/type.hpp>

#include <format>
#include <numeric>

namespace pdb {

namespace {

std::string visualizeMemberPointerType(const TypedData& data)
{
    return std::format("0x{:x}", fromBytes<std::uintptr_t>(data.dataPtr()));
}

std::string visualizePointerType(const Process& proc, const TypedData& data)
{
    auto ptr = fromBytes<uint64_t>(data.dataPtr());
    if(ptr == 0) {
        return "0x0";
    }
    if(data.valueType().getDie()[DW_AT_type].asType().isCharType()) {
        return std::format("\"{}\"", proc.readString(VirtAddr{ptr}));
    }
    return std::format("0x{:x}", ptr);
}

std::string visualizeClassType(const Process& proc, const TypedData& data, int depth)
{
    std::string ret = "{\n";
    for(auto& child : data.valueType().getDie().children()) {
        if(child.abbrevEntry()->tag == DW_TAG_member && child.contains(DW_AT_data_member_location)
           || child.contains(DW_AT_data_bit_offset)) {
            auto indent     = std::string(depth + 1, '\t');
            auto byteOffset = child.contains(DW_AT_data_member_location)
                                ? child[DW_AT_data_member_location].asInt()
                                : child[DW_AT_bit_offset].asInt() / 8;
            auto pos        = data.dataPtr() + byteOffset;
            auto subtype    = child[DW_AT_type].asType();
            std::vector<std::byte> memberData{pos, pos + subtype.byteSize()};
            auto data      = TypedData{memberData, subtype}.fixupBitfield(proc, child);
            auto memberStr = data.visualize(proc, depth + 1);
            auto name      = child.name().value_or("<unnamed>");
            ret += std::format("{}{}: {}\n", indent, name, memberStr);
        }
    }
    auto indent = std::string(depth, '\t');
    ret += indent + "}";
    return ret;
}

} // namespace

size_t Type::byteSize() const
{
    if(!m_byteSize.has_value()) {
        m_byteSize = computeByteSize();
    }
    return *m_byteSize;
}

bool Type::isCharType() const
{
    auto stripped = stripCvTypedef().getDie();
    if(!stripped.contains(DW_AT_encoding)) {
        return false;
    }
    auto encoding = stripped[DW_AT_encoding].asInt();
    return stripped.abbrevEntry()->tag == DW_TAG_base_type
        && (encoding == DW_ATE_signed_char || encoding == DW_ATE_unsigned_char);
}

size_t Type::computeByteSize() const
{
    auto tag = m_die.abbrevEntry()->tag;

    if(tag == DW_TAG_pointer_type) {
        return 8;
    }

    if(tag == DW_TAG_ptr_to_member_type) {
        auto memberType = m_die[DW_AT_type].asType();
        if(memberType.getDie().abbrevEntry()->tag == DW_TAG_subroutine_type) {
            return 16;
        }
        return 8;
    }
    if(tag == DW_TAG_array_type) {
        auto valueSize = m_die[DW_AT_type].asType().byteSize();
        for(auto& child : m_die.children()) {
            if(child.abbrevEntry()->tag == DW_TAG_subrange_type) {
                valueSize *= child[DW_AT_upper_bound].asInt() + 1;
            }
        }
        return valueSize;
    }

    if(m_die.contains(DW_AT_byte_size)) {
        return m_die[DW_AT_byte_size].asInt();
    }
    if(m_die.contains(DW_AT_type)) {
        return m_die[DW_AT_type].asType().byteSize();
    }

    return 0;
}

TypedData TypedData::fixupBitfield(const Process& proc, const Die& memberDie) const
{
    auto stripped     = m_type.stripCvTypedef();
    auto bitfieldInfo = memberDie.getBitfieldInformation(stripped.byteSize());
    if(bitfieldInfo) {
        auto [bitSize, storageByteSize, bitOffset] = *bitfieldInfo;

        std::vector<std::byte> fixedData;
        fixedData.resize(storageByteSize);

        auto dest = reinterpret_cast<uint8_t*>(fixedData.data());
        auto src  = reinterpret_cast<const uint8_t*>(m_data.data());
        memcpyBits(dest, 0, src, bitOffset, bitSize);

        return {fixedData, m_type};
    }
    return *this;
}

std::string visualizeSubrange(const Process& proc, const Type& valueType,
                              Span<const std::byte> data, std::vector<size_t> dimensions)
{
    if(dimensions.empty()) {
        std::vector<std::byte> dataVec{data.begin(), data.end()};
        return TypedData{std::move(dataVec), valueType}.visualize(proc);
    }
    std::string ret = "[";
    auto size       = dimensions.back();
    dimensions.pop_back();
    auto subSize = std::accumulate(dimensions.begin(), dimensions.end(), valueType.byteSize(),
                                   std::multiplies<>());
    for(size_t i = 0; i < size; ++i) {
        Span<const std::byte> subdata{data.begin() + i * subSize, data.end()};
        ret += visualizeSubrange(proc, valueType, subdata, dimensions);

        if(i != size - 1) {
            ret += ", ";
        }
    }
    return ret + "]";
}

std::string visualizeArrayType(const Process& proc, const TypedData& data)
{
    std::vector<size_t> dimensions;
    for(auto& child : data.valueType().getDie().children()) {
        if(child.abbrevEntry()->tag == DW_TAG_subrange_type) {
            dimensions.push_back(child[DW_AT_upper_bound].asInt() + 1);
        }
    }
    std::reverse(dimensions.begin(), dimensions.end());
    auto valueType = data.valueType().getDie()[DW_AT_type].asType();
    return visualizeSubrange(proc, valueType, data.data(), dimensions);
}

std::string visualizeBaseType(const TypedData& data)
{
    auto& type = data.valueType();
    auto die   = type.getDie();
    auto ptr   = data.dataPtr();

    switch(die[DW_AT_encoding].asInt()) {
        case DW_ATE_boolean:
            return fromBytes<bool>(ptr) ? "true" : "false";
        case DW_ATE_float:
            if(die.name() == "float") {
                return std::format("{}", fromBytes<float>(ptr));
            }
            if(die.name() == "double") {
                return std::format("{}", fromBytes<double>(ptr));
            }
            if(die.name() == "long double") {
                return std::format("{}", fromBytes<long double>(ptr));
            }
            Error::send("Unsupported floating point type");
        case DW_ATE_signed:
            switch(type.byteSize()) {
                case 1:
                    return std::format("{}", fromBytes<int8_t>(ptr));
                case 2:
                    return std::format("{}", fromBytes<int16_t>(ptr));
                case 4:
                    return std::format("{}", fromBytes<int32_t>(ptr));
                case 8:
                    return std::format("{}", fromBytes<int64_t>(ptr));
                default:
                    Error::send("Unsupported signed integer type");
            }
        case DW_ATE_unsigned:
            switch(type.byteSize()) {
                case 1:
                    return std::format("{}", fromBytes<uint8_t>(ptr));
                case 2:
                    return std::format("{}", fromBytes<uint16_t>(ptr));
                case 4:
                    return std::format("{}", fromBytes<uint32_t>(ptr));
                case 8:
                    return std::format("{}", fromBytes<uint64_t>(ptr));
                default:
                    Error::send("Unsupported unsigned integer type");
            }
        case DW_ATE_signed_char:
            return std::format("{}", fromBytes<signed char>(ptr));
        case DW_ATE_unsigned_char:
            return std::format("{}", fromBytes<unsigned char>(ptr));
        case DW_ATE_UTF:
            Error::send("DW_ATE_UTF not implemented");
        default:
            Error::send("Unsupported encoding");
    }
}

std::string TypedData::visualize(const Process& proc, int depth) const
{
    auto die = m_type.getDie();
    switch(die.abbrevEntry()->tag) {
        case DW_TAG_base_type:
            return visualizeBaseType(*this);
        case DW_TAG_pointer_type:
            return visualizePointerType(proc, *this);
        case DW_TAG_ptr_to_member_type:
            return visualizeMemberPointerType(*this);
        case DW_TAG_array_type:
            return visualizeArrayType(proc, *this);
        case DW_TAG_class_type:
        case DW_TAG_structure_type:
        case DW_TAG_union_type:
            return visualizeClassType(proc, *this, depth);
        case DW_TAG_enumeration_type:
        case DW_TAG_typedef:
        case DW_TAG_const_type:
        case DW_TAG_volatile_type:
            return TypedData{m_data, die[DW_AT_type].asType()}.visualize(proc);
        default:
            Error::send("Unsupported type");
    }
}

TypedData TypedData::derefPointer(const Process& proc) const
{
    auto strippedTypeDie = m_type.stripCvTypedef().getDie();
    auto tag             = strippedTypeDie.abbrevEntry()->tag;
    if(tag != DW_TAG_pointer_type) {
        Error::send("Not a pointer type");
    }
    VirtAddr address{fromBytes<uint64_t>(m_data.data())};
    auto valueType = strippedTypeDie[DW_AT_type].asType();
    auto dataVec   = proc.readMemory(address, valueType.byteSize());
    return {std::move(dataVec), valueType, address};
}

TypedData TypedData::readMember(const Process& proc, std::string_view memberName) const
{
    auto die      = m_type.getDie();
    auto children = die.children();
    auto it       = std::find_if(children.begin(), children.end(),
                                 [&](auto& child) { return child.name().value_or("") == memberName; });

    if(it == children.end()) {
        Error::send("No such member");
    }

    auto var       = *it;
    auto valueType = var[DW_AT_type].asType();

    auto byteOffset = var.contains(DW_AT_data_member_location)
                        ? var[DW_AT_data_member_location].asInt()
                        : var[DW_AT_bit_offset].asInt() / 8;
    auto dataStart  = m_data.begin() + byteOffset;
    std::vector<std::byte> memberData{dataStart, dataStart + valueType.byteSize()};

    auto data = m_address ? TypedData{std::move(memberData), valueType, *m_address + byteOffset}
                          : TypedData{std::move(memberData), valueType};
    return data.fixupBitfield(proc, var);
}

TypedData TypedData::index(const Process& proc, size_t index)
{
    auto parentType = m_type.stripCvRefTypedef().getDie();
    auto tag        = parentType.abbrevEntry()->tag;
    if(tag != DW_TAG_array_type && tag != DW_TAG_pointer_type) {
        Error::send("Not an array or pointer type");
    }
    auto valueType   = parentType[DW_AT_type].asType();
    auto elementSize = valueType.byteSize();
    auto offset      = index * elementSize;
    if(tag == DW_TAG_pointer_type) {
        VirtAddr address{fromBytes<uint64_t>(m_data.data())};
        address += offset;
        auto dataVec = proc.readMemory(address, elementSize);
        return {std::move(dataVec), valueType, address};
    } else {
        std::vector<std::byte> dataVec{m_data.begin() + offset,
                                       m_data.begin() + offset + elementSize};
        if(m_address) {
            return {std::move(dataVec), valueType, *m_address + offset};
        }
        return {std::move(dataVec), valueType};
    }
}

} // namespace pdb

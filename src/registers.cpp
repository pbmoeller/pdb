#include <libpdb/bit.hpp>
#include <libpdb/process.hpp>
#include <libpdb/registers.hpp>

#include <iostream>

namespace pdb {

namespace {

template<typename T>
byte128 widen(const RegisterInfo& info, T t)
{
    if constexpr(std::is_floating_point_v<T>) {
        if(info.format == RegisterFormat::DOUBLE_FLOAT) {
            return toByte128(static_cast<double>(t));
        }
        if(info.format == RegisterFormat::LONG_DOUBLE) {
            return toByte128(static_cast<long double>(t));
        }
    } else if constexpr(std::is_signed_v<T>) {
        if(info.format == RegisterFormat::UINT) {
            switch(info.size) {
                case 2:
                    return toByte128(static_cast<int16_t>(t));
                case 4:
                    return toByte128(static_cast<int32_t>(t));
                case 8:
                    return toByte128(static_cast<int64_t>(t));
            }
        }
    }

    return toByte128(t);
}

} // namespace

Registers::Value Registers::read(const RegisterInfo& info) const
{
    if(isUndefined(info.id)) {
        Error::send("Register is undefined");
    }

    auto bytes = asBytes(m_data);
    if(info.format == RegisterFormat::UINT) {
        switch(info.size) {
            case 1:
                return fromBytes<uint8_t>(bytes + info.offset);
            case 2:
                return fromBytes<uint16_t>(bytes + info.offset);
            case 4:
                return fromBytes<uint32_t>(bytes + info.offset);
            case 8:
                return fromBytes<uint64_t>(bytes + info.offset);
            default:
                Error::send("Unsupported register size for UINT format");
        }
    } else if(info.format == RegisterFormat::DOUBLE_FLOAT) {
        return fromBytes<double>(bytes + info.offset);
    } else if(info.format == RegisterFormat::LONG_DOUBLE) {
        return fromBytes<long double>(bytes + info.offset);
    } else if(info.format == RegisterFormat::VECTOR && info.size == 8) {
        return fromBytes<byte64>(bytes + info.offset);
    } else {
        return fromBytes<byte128>(bytes + info.offset);
    }
}

void Registers::write(const RegisterInfo& info, Value value, bool commit)
{
    auto bytes = asBytes(m_data);

    std::visit(
        [&](auto& v) {
            if(sizeof(v) <= info.size) {
                auto wide       = widen(info, v);
                auto valueBytes = asBytes(wide);
                std::copy(valueBytes, valueBytes + info.size, bytes + info.offset);
            } else {
                std::cerr << "pdb::Registers::write called with mismatched size and offset";
                std::terminate();
            }
        },
        value);

    if(commit) {
        if(info.type == RegisterType::FPR) {
            m_proc->writeFprs(m_data.i387);
        } else {
            auto alignedOffset = info.offset & ~0b111;
            m_proc->writeUserArea(alignedOffset, fromBytes<uint64_t>(bytes + alignedOffset));
        }
    }
}

bool Registers::isUndefined(RegisterId id) const
{
    size_t canonicalOffset = registerInfoById(id).offset >> 1;
    return std::find(begin(m_undefined), end(m_undefined), canonicalOffset) != end(m_undefined);
}

void Registers::undefine(RegisterId id)
{
    size_t canonicalOffset = registerInfoById(id).offset >> 1;
    m_undefined.push_back(canonicalOffset);
}

void Registers::flush()
{
    m_proc->writeFprs(m_data.i387);
    m_proc->writeGprs(m_data.regs);
    auto info = registerInfoById(RegisterId::dr0);
    for(auto i = 0; i < 8; ++i) {
        if(i == 4 || i == 5) {
            continue;
        }
        auto regOffset = info.offset + sizeof(uint64_t) * i;
        auto ptr       = reinterpret_cast<std::byte*>(m_data.u_debugreg + i);
        auto bytes     = fromBytes<uint64_t>(ptr);
        m_proc->writeUserArea(regOffset, bytes);
    }
}

} // namespace pdb

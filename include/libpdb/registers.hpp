#ifndef LIBPDB_REGISTERS_HPP
#define LIBPDB_REGISTERS_HPP

#include <libpdb/register_info.hpp>
#include <libpdb/types.hpp>

#include <sys/user.h>

#include <variant>

namespace pdb {

class Process;

class Registers
{
public:
    Registers()                            = delete;
    Registers(const Registers&)            = delete;
    Registers& operator=(const Registers&) = delete;

    using Value = std::variant<uint8_t, uint16_t, uint32_t, uint64_t, int8_t, int16_t, int32_t,
                               int64_t, float, double, long double, byte64, byte128>;
    Value read(const RegisterInfo& info) const;
    void write(const RegisterInfo& info, Value value);

    template<typename T>
    T readByIdAs(RegisterId id) const {
        return std::get<T>(read(registerInfoById(id)));
    }

    template<typename T>
    void writeById(RegisterId id, Value value) {
        write(registerInfoById(id), value);
    }

private:
    friend Process;
    Registers(Process& proc)
        : m_proc(&proc)
    { }

private:
    user m_data;
    Process* m_proc;
};

} // namespace pdb

#endif // LIBPDB_REGISTERS_HPP

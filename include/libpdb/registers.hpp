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
    Registers()                            = default;
    Registers(const Registers&)            = default;
    Registers& operator=(const Registers&) = default;

    using Value = std::variant<uint8_t, uint16_t, uint32_t, uint64_t, int8_t, int16_t, int32_t,
                               int64_t, float, double, long double, byte64, byte128>;
    Value read(const RegisterInfo& info) const;
    void write(const RegisterInfo& info, Value value, bool commit = true);

    template<typename T>
    T readByIdAs(RegisterId id) const {
        return std::get<T>(read(registerInfoById(id)));
    }

    void writeById(RegisterId id, Value value, bool commit = true) {
        write(registerInfoById(id), value, commit);
    }

    bool isUndefined(RegisterId id) const;
    void undefine(RegisterId id);

    VirtAddr cfa() const { return m_cfa; }
    void setCfa(VirtAddr addr) { m_cfa = addr; }
    void flush();

private:
    friend Process;
    Registers(Process& proc)
        : m_proc(&proc)
    { }

private:
    user m_data;
    Process* m_proc;
    std::vector<size_t> m_undefined;
    VirtAddr m_cfa;
};

} // namespace pdb

#endif // LIBPDB_REGISTERS_HPP

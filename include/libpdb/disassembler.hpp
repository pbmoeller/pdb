#ifndef LIBPDB_DISASSEMBLER_HPP
#define LIBPDB_DISASSEMBLER_HPP

#include <libpdb/process.hpp>

#include <optional>

namespace pdb {

class Disassembler
{
    struct Instruction
    {
        VirtAddr address;
        std::string text;
    };

public:
    Disassembler(Process& proc);

    std::vector<Instruction> disassemble(size_t instructions,
                                         std::optional<VirtAddr> address = std::nullopt);

private:
    Process* m_process;
};

} // namespace pdb

#endif // LIBPDB_DISASSEMBLER_HPP

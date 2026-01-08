#include <libpdb/disassembler.hpp>

#include <Zydis/Zydis.h>

namespace pdb {

Disassembler::Disassembler(Process& proc)
    : m_process(&proc)
{ }

std::vector<Disassembler::Instruction> Disassembler::disassemble(size_t instructions,
                                                                 std::optional<VirtAddr> address)
{
    std::vector<Instruction> ret;
    ret.reserve(instructions);

    if(!address) {
        address.emplace(m_process->getProgramCounter());
    }

    auto code = m_process->readMemoryWithoutTraps(*address, instructions * 15);

    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instr;

    while(ZYAN_SUCCESS(ZydisDisassembleATT(ZYDIS_MACHINE_MODE_LONG_64, address->addr(),
                                           code.data() + offset, code.size() - offset, &instr))
          && instructions > 0) {
        ret.push_back(Instruction{*address, std::string(instr.text)});
        offset += instr.info.length;
        *address += instr.info.length;
        --instructions;
    }

    return ret;
}

} // namespace pdb

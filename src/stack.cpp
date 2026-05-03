#include <libpdb/stack.hpp>
#include <libpdb/target.hpp>

namespace pdb {

void Stack::resetInlineHeight()
{
    auto stack = inlineStackAtPc();

    m_inlineHeight = 0;
    auto pc        = m_target->getPcFileAddress();
    for(auto it = stack.rbegin(); it != stack.rend() && it->lowPc() == pc; ++it) {
        ++m_inlineHeight;
    }
}

std::vector<Die> Stack::inlineStackAtPc() const
{
    auto pc = m_target->getPcFileAddress();
    if(!pc.elfFile()) {
        return {};
    }
    return pc.elfFile()->getDwarf().inlineStackAtAddress(pc);
}

void Stack::unwind()
{
    resetInlineHeight();
    m_currentFrame = m_inlineHeight;

    auto virtPc = m_target->getProcess().getProgramCounter();
    auto filePc = m_target->getPcFileAddress();
    auto& proc  = m_target->getProcess();
    auto regs   = proc.getRegisters();

    m_frames.clear();

    auto elf = filePc.elfFile();
    if(!elf) {
        return;
    }

    while(virtPc.addr() != 0 && elf == &m_target->getElf()) {
        auto& dwarf      = elf->getDwarf();
        auto inlineStack = dwarf.inlineStackAtAddress(filePc);
        if(inlineStack.empty()) {
            return;
        }

        if(inlineStack.size() > 1) {
            createBaseFrame(regs, inlineStack, filePc, true);
            createInlineStackFrames(regs, inlineStack, filePc);
        } else {
            createBaseFrame(regs, inlineStack, filePc, false);
        }
        regs   = dwarf.cfi().unwind(proc, filePc, m_frames.back().regs);
        virtPc = VirtAddr{regs.readByIdAs<uint64_t>(RegisterId::rip) - 1};
        filePc = virtPc.toFileAddr(m_target->getElf());
        elf    = filePc.elfFile();
    }
}

Span<const StackFrame> Stack::frames() const
{
    return {m_frames.data() + m_inlineHeight, m_frames.size() - m_inlineHeight};
}

const Registers& Stack::regs() const
{
    return m_frames[m_currentFrame].regs;
}

VirtAddr Stack::getPc() const
{
    return VirtAddr{regs().readByIdAs<uint64_t>(RegisterId::rip)};
}

void Stack::createInlineStackFrames(const Registers& regs, const std::vector<Die> inlineStack,
                                    FileAddr pc)
{
    for(auto it = inlineStack.rbegin() + 1; it != inlineStack.rend(); ++it) {
        auto inlinedPc = std::prev(it)->lowPc().toVirtAddr();
        m_frames.push_back(StackFrame{regs, inlinedPc, *it});
        m_frames.back().inlined = std::next(it) != inlineStack.rend();
        m_frames.back().location = std::prev(it)->location();
    }
}

void Stack::createBaseFrame(const Registers& regs, const std::vector<Die> inlineStack, FileAddr pc,
                           bool inlined)
{
    auto backtracePc = pc.toVirtAddr();
    auto lineyEntry  = pc.elfFile()->getDwarf().lineEntryAtAddress(pc);
    if(lineyEntry != LineTable::Iterator{}) {
        backtracePc = lineyEntry->address.toVirtAddr();
    }

    m_frames.push_back({regs, backtracePc, inlineStack.back(), inlined});
    m_frames.back().location = SourceLocation{lineyEntry->fileEntry, lineyEntry->line};
}

} // namespace pdb

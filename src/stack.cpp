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

} // namespace pdb

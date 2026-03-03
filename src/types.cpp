#include <libpdb/elf.hpp>
#include <libpdb/types.hpp>

#include <cassert>

namespace pdb {

FileAddr VirtAddr::toFileAddr(const Elf& obj) const
{
    auto section = obj.getSectionContainingAddress(*this);
    if(!section) {
        return FileAddr{};
    }
    return FileAddr{obj, m_addr - obj.loadBias().addr()};
}

VirtAddr FileAddr::toVirtAddr() const
{
    assert(m_elf && "VirtAddr called on null address");
    auto section = m_elf->getSectionContainingAddress(*this);
    if(!section) {
        return VirtAddr{};
    }
    return VirtAddr{m_addr + m_elf->loadBias().addr()};
}

} // namespace pdb

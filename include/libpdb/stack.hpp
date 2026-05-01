#ifndef LIBPDB_STACK_HPP
#define LIBPDB_STACK_HPP

#include <libpdb/dwarf.hpp>

#include <vector>

namespace pdb {

class Target;
class Stack
{
public:
    Stack(Target* target)
        : m_target(target)
    { }

    void resetInlineHeight();
    std::vector<Die> inlineStackAtPc() const;
    uint32_t inlineHeight() const { return m_inlineHeight; }
    const Target& getTarget() const { return *m_target; }

    void simulateInlinedStepIn() {
        --m_inlineHeight;
    }

private:
    Target* m_target{nullptr};
    uint32_t m_inlineHeight{0};
};

} // namespace pdb

#endif // LIBPDB_STACK_HPP

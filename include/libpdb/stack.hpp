#ifndef LIBPDB_STACK_HPP
#define LIBPDB_STACK_HPP

#include <libpdb/dwarf.hpp>

#include <vector>

namespace pdb {

struct StackFrame
{
    Registers regs;
    VirtAddr backtraceReportAddress;
    Die funcDie;
    bool inlined{false};
    SourceLocation location;
};

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

    void simulateInlinedStepIn()
    {
        --m_inlineHeight;
        m_currentFrame = m_inlineHeight;
    }

    void unwind();
    void up() { ++m_currentFrame; }
    void down() { --m_currentFrame; }

    Span<const StackFrame> frames() const;
    bool hasFrames() const { return !m_frames.empty(); }
    const StackFrame& currentFrame() const { return m_frames[m_currentFrame]; }

    size_t currentFrameIndex() const { return m_currentFrame - m_inlineHeight; }

    const Registers& regs() const;
    VirtAddr getPc() const;

private:
    void createInlineStackFrames(const Registers& regs, const std::vector<Die> inlineStack,
                                 FileAddr pc);
    void createBaseFrame(const Registers& regs, const std::vector<Die> inlineStack, FileAddr pc,
                        bool inlined);

private:
    Target* m_target{nullptr};
    uint32_t m_inlineHeight{0};
    std::vector<StackFrame> m_frames;
    size_t m_currentFrame{0};
};

} // namespace pdb

#endif // LIBPDB_STACK_HPP

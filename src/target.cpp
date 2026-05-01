#include <libpdb/bit.hpp>
#include <libpdb/disassembler.hpp>
#include <libpdb/target.hpp>
#include <libpdb/types.hpp>

#include <cxxabi.h>

#include <csignal>
#include <optional>

namespace pdb {

namespace {

std::unique_ptr<Elf> createLoadedElf(const Process& proc, const std::filesystem::path& path)
{
    auto auxv = proc.getAuxv();
    auto obj  = std::make_unique<Elf>(path);
    obj->notifyLoaded(VirtAddr{auxv[AT_ENTRY] - obj->header().e_entry});
    return obj;
}

} // namespace

std::unique_ptr<Target> Target::launch(std::filesystem::path path,
                                       std::optional<int> stdoutReplacement)
{
    auto proc   = Process::launch(path, true, stdoutReplacement);
    auto obj    = createLoadedElf(*proc, path);
    auto target = std::unique_ptr<Target>(new Target(std::move(proc), std::move(obj)));
    target->getProcess().setTarget(target.get());
    return target;
}

std::unique_ptr<Target> Target::attach(pid_t pid)
{
    auto elfPath = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto proc    = Process::attach(pid);
    auto obj     = createLoadedElf(*proc, elfPath);
    auto target  = std::unique_ptr<Target>(new Target(std::move(proc), std::move(obj)));
    target->getProcess().setTarget(target.get());
    return target;
}

void Target::notifyStop(const StopReason& reason)
{
    m_stack.resetInlineHeight();
}

FileAddr Target::getPcFileAddress() const
{
    return m_process->getProgramCounter().toFileAddr(*m_elf);
}

StopReason Target::stepIn()
{
    auto& stack = getStack();
    if(stack.inlineHeight() > 0) {
        stack.simulateInlinedStepIn();
        return StopReason(ProcessState::Stopped, SIGTRAP, TrapType::SingleStep);
    }
    auto origLine = lineEntryAtPc();
    do {
        auto reason = m_process->stepInstruction();
        if(!reason.isStep()) {
            return reason;
        }
    } while((lineEntryAtPc() == origLine || lineEntryAtPc()->endSequence)
            && lineEntryAtPc() != LineTable::Iterator{});

    auto pc = getPcFileAddress();
    if(pc.elfFile() != nullptr) {
        auto& dwarf = pc.elfFile()->getDwarf();
        auto func   = dwarf.functionContainingAddress(pc);
        if(func && func->lowPc() == pc) {
            auto line = lineEntryAtPc();
            if(line != LineTable::Iterator{}) {
                ++line;
                return runUntilAddress(line->address.toVirtAddr());
            }
        }
    }
    return StopReason(ProcessState::Stopped, SIGTRAP, TrapType::SingleStep);
}

StopReason Target::stepOver()
{
    auto origLine = lineEntryAtPc();
    Disassembler disas(*m_process);
    StopReason reason;
    auto& stack = getStack();
    do {
        auto inlineStack          = stack.inlineStackAtPc();
        auto atStartOfInlineFrame = stack.inlineHeight() > 0;
        if(atStartOfInlineFrame) {
            auto frameToSkip   = inlineStack[inlineStack.size() - stack.inlineHeight()];
            auto returnAddress = frameToSkip.highPc().toVirtAddr();
            reason             = runUntilAddress(returnAddress);
            if(!reason.isStep() || m_process->getProgramCounter() != returnAddress) {
                return reason;
            }
        } else if(auto instructions = disas.disassemble(2, m_process->getProgramCounter());
                  instructions[0].text.rfind("call") == 0) {
            reason = runUntilAddress(instructions[1].address);
            if(!reason.isStep() || m_process->getProgramCounter() != instructions[1].address) {
                return reason;
            }
        } else {
            reason = m_process->stepInstruction();
            if(!reason.isStep()) {
                return reason;
            }
        }
    } while((lineEntryAtPc() == origLine || lineEntryAtPc()->endSequence)
            && lineEntryAtPc() != LineTable::Iterator{});
    return reason;
}

StopReason Target::stepOut()
{
    auto& stack          = getStack();
    auto inlineStack     = stack.inlineStackAtPc();
    auto hasInlineFrames = inlineStack.size() > 1;
    auto atInlineFrame   = stack.inlineHeight() < inlineStack.size() - 1;

    if(hasInlineFrames && atInlineFrame) {
        auto currentFrame  = inlineStack[inlineStack.size() - stack.inlineHeight() - 1];
        auto returnAddress = currentFrame.highPc().toVirtAddr();
        return runUntilAddress(returnAddress);
    }

    auto framePointer  = m_process->getRegisters().readByIdAs<uint64_t>(RegisterId::rbp);
    auto returnAddress = m_process->readMemoryAs<uint64_t>(VirtAddr{framePointer + 8});
    return runUntilAddress(VirtAddr{returnAddress});
}

LineTable::Iterator Target::lineEntryAtPc() const
{
    auto pc = getPcFileAddress();
    if(!pc.elfFile()) {
        return LineTable::Iterator();
    }
    auto cu = pc.elfFile()->getDwarf().compileUnitContainingAddress(pc);
    if(!cu) {
        return LineTable::Iterator();
    }
    return cu->lines().getEntryByAddress(pc);
}

StopReason Target::runUntilAddress(VirtAddr address)
{
    BreakpointSite* breakpointToRemove = nullptr;
    if(!m_process->breakpointSites().containsAddress(address)) {
        breakpointToRemove = &m_process->createBreakpointSite(address, false, true);
        breakpointToRemove->enable();
    }

    m_process->resume();
    auto reason = m_process->waitOnSignal();
    if(reason.isBreakpoint() && m_process->getProgramCounter() == address) {
        reason.trapReason = TrapType::SingleStep;
    }

    if(breakpointToRemove) {
        m_process->breakpointSites().removeByAddress(breakpointToRemove->address());
    }
    return reason;
}

Target::FindFunctionResult Target::findFunctions(std::string name) const
{
    FindFunctionResult result;

    auto dwarfFound = m_elf->getDwarf().findFunctions(name);
    if(dwarfFound.empty()) {
        auto elfFound = m_elf->getSymbolsByName(name);
        for(auto sym : elfFound) {
            result.elfFunctions.push_back(std::pair{m_elf.get(), sym});
        }
    } else {
        result.dwarfFunctions.insert(result.dwarfFunctions.end(), dwarfFound.begin(),
                                     dwarfFound.end());
    }
    return result;
}

Breakpoint& Target::createAddressBreakpoint(VirtAddr address, bool hardware, bool internal)
{
    return m_breakpoints.push(std::unique_ptr<AddressBreakpoint>(
        new AddressBreakpoint(*this, address, hardware, internal)));
}

Breakpoint& Target::createFunctionBreakpoint(std::string functionName, bool hardware, bool internal)
{
    return m_breakpoints.push(std::unique_ptr<FunctionBreakpoint>(
        new FunctionBreakpoint(*this, functionName, hardware, internal)));
}

Breakpoint& Target::createLineBreakpoint(std::filesystem::path file, size_t line, bool hardware,
                                         bool internal)
{
    return m_breakpoints.push(
        std::unique_ptr<LineBreakpoint>(new LineBreakpoint(*this, file, line, hardware, internal)));
}

std::string Target::functionNameAtAddress(VirtAddr address) const
{
    auto fileAddress = address.toFileAddr(*m_elf);
    auto obj         = fileAddress.elfFile();
    if(!obj) {
        return "";
    }

    auto func = obj->getDwarf().functionContainingAddress(fileAddress);
    if(func && func->name()) {
        return std::string{*func->name()};
    } else if(auto elfFunc = obj->getSymbolContainingAddress(fileAddress);
              elfFunc && ELF64_ST_TYPE(elfFunc.value()->st_info) == STT_FUNC) {
        auto elfName = std::string{obj->getString(elfFunc.value()->st_name)};
        return abi::__cxa_demangle(elfName.c_str(), nullptr, nullptr, nullptr);
    }
    return "";
}

} // namespace pdb

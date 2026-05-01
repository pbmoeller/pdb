#include <libpdb/breakpoint.hpp>
#include <libpdb/target.hpp>

namespace pdb {

namespace {

auto getNextId()
{
    static Breakpoint::IdType id = 0;
    return ++id;
}

} // namespace

void Breakpoint::enable()
{
    m_isEnabled = true;
    m_breakpointSites.forEach([](auto& site) { site.enable(); });
}

void Breakpoint::disable()
{
    m_isEnabled = false;
    m_breakpointSites.forEach([](auto& site) { site.disable(); });
}

Breakpoint::Breakpoint(Target& target, bool isHardware, bool isInternal)
    : m_target{&target}
    , m_isHardware{isHardware}
    , m_isInternal{isInternal}
{
    m_id = isInternal ? -1 : getNextId();
}

void FunctionBreakpoint::resolve()
{
    auto foundFunctions = m_target->findFunctions(m_functionName);
    for(auto die : foundFunctions.dwarfFunctions) {
        if(die.contains(DW_AT_low_pc) || die.contains(DW_AT_ranges)) {
            FileAddr addr;
            if(die.abbrevEntry()->tag == DW_TAG_inlined_subroutine) {
                addr = die.lowPc();
            } else {
                auto functionLine = die.cu()->lines().getEntryByAddress(die.lowPc());
                ++functionLine;
                addr = functionLine->address;
            }
            auto loadAddress = addr.toVirtAddr();

            if(!breakpointSites().containsAddress(loadAddress)) {
                auto& newSite = m_target->getProcess().createBreakpointSite(
                    this, m_nextSiteId++, loadAddress, m_isHardware, m_isInternal);
                breakpointSites().push(&newSite);
                if(m_isEnabled) {
                    newSite.enable();
                }
            }
        }
    }

    for(auto sym : foundFunctions.elfFunctions) {
        auto fileAddress = FileAddr{*sym.first, sym.second->st_value};
        auto loadAddress = fileAddress.toVirtAddr();
        if(!m_breakpointSites.containsAddress(loadAddress)) {
            auto& newSite = m_target->getProcess().createBreakpointSite(
                this, m_nextSiteId++, loadAddress, m_isHardware, m_isInternal);
            m_breakpointSites.push(&newSite);
            if(m_isEnabled) {
                newSite.enable();
            }
        }
    }
}

void LineBreakpoint::resolve()
{
    auto& dwarf = m_target->getElf().getDwarf();
    for(auto& cu : dwarf.compileUnits()) {
        auto entries = cu->lines().getEntriesByLine(m_file, m_line);
        for(auto entry : entries) {
            auto& dwarf = entry->address.elfFile()->getDwarf();
            auto stack  = dwarf.inlineStackAtAddress(entry->address);

            auto noInlineStack = stack.size() == 1;
            auto shouldSkipPrologue =
                noInlineStack
                && (stack[0].contains(DW_AT_ranges) || stack[0].contains(DW_AT_low_pc))
                && stack[0].lowPc() == entry->address;
            if(shouldSkipPrologue) {
                ++entry;
            }
            auto loadAddress = entry->address.toVirtAddr();
            if(!m_breakpointSites.containsAddress(loadAddress)) {
                auto& newSite = m_target->getProcess().createBreakpointSite(
                    this, m_nextSiteId++, loadAddress, m_isHardware, m_isInternal);
                m_breakpointSites.push(&newSite);
                if(m_isEnabled) {
                    newSite.enable();
                }
            }
        }
    }
}

void AddressBreakpoint::resolve()
{
    if(m_breakpointSites.empty()) {
        auto& newSite = m_target->getProcess().createBreakpointSite(this, m_nextSiteId++, m_address,
                                                                    m_isHardware, m_isInternal);
        m_breakpointSites.push(&newSite);
        if(m_isEnabled) {
            newSite.enable();
        }
    }
}

} // namespace pdb

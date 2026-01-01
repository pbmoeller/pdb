#include <libpdb/breakpoint_site.hpp>

namespace pdb {

namespace {

auto getNextId()
{
    static BreakpointSite::IdType id = 0;
    return ++id;
}

} // namespace

BreakpointSite::BreakpointSite(Process& process, VirtAddr address)
    : m_process{&process}
    , m_address{address}
    , m_isEnabled{false}
    , m_savedData{}
{
    m_id = getNextId();
}

} // namespace pdb

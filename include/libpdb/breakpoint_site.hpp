#ifndef LIBPDB_BREAKPOINT_SITE_HPP
#define LIBPDB_BREAKPOINT_SITE_HPP

#include <libpdb/types.hpp>

#include <cstddef>
#include <cstdint>

namespace pdb {

class Breakpoint;
class Process;

class BreakpointSite
{
public:
    BreakpointSite()                                 = delete;
    BreakpointSite(const BreakpointSite&)            = delete;
    BreakpointSite& operator=(const BreakpointSite&) = delete;

    using IdType = int32_t;
    IdType id() const { return m_id; }

    void enable();
    void disable();

    bool isEnabled() const { return m_isEnabled; }
    VirtAddr address() const { return m_address; }

    bool atAddress(VirtAddr addr) { return m_address == addr; }
    bool inRange(VirtAddr low, VirtAddr high) const
    {
        return low <= m_address && high >= m_address;
    }

    bool isHardware() { return m_isHardware; }
    bool isInternal() { return m_isInternal; }

private:
    friend Process;
    BreakpointSite(Process& process, VirtAddr address,
                   bool isHardware = false, bool isInternal = false);
    BreakpointSite(Breakpoint* parent, IdType id, Process& process, VirtAddr address,
                   bool isHardware = false, bool isInternal = false);

private:
    Breakpoint *m_parent{nullptr};
    IdType m_id;
    Process* m_process;
    VirtAddr m_address;
    bool m_isEnabled;
    std::byte m_savedData;
    bool m_isHardware;
    bool m_isInternal;
    int m_hardwareRegisterIndex{-1};
};

} // namespace pdb

#endif // LIBPDB_BREAKPOINT_SITE_HPP

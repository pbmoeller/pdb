#include <libpdb/breakpoint_site.hpp>
#include <libpdb/error.hpp>
#include <libpdb/process.hpp>

#include <sys/ptrace.h>

namespace pdb {

namespace {

auto getNextId()
{
    static BreakpointSite::IdType id = 0;
    return ++id;
}

} // namespace

BreakpointSite::BreakpointSite(Process& process, VirtAddr address, bool isHardware, bool isInternal)
    : m_process{&process}
    , m_address{address}
    , m_isEnabled{false}
    , m_savedData{}
    , m_isHardware{isHardware}
    , m_isInternal{isInternal}
{
    m_id = m_isInternal ? -1 : getNextId();
}

void BreakpointSite::enable()
{
    if(m_isEnabled) {
        return;
    }

    if(m_isHardware) {
        m_hardwareRegisterIndex = m_process->setHardwareBreakpoint(m_id, m_address);
    } else {
        errno         = 0;
        uint64_t data = ptrace(PTRACE_PEEKDATA, m_process->pid(), m_address, nullptr);
        if(errno != 0) {
            Error::sendErrno("Enabling BreakpointSite failed");
        }

        m_savedData           = static_cast<std::byte>(data & 0xFF);
        uint64_t int3         = 0xCC;
        uint64_t dataWithInt3 = ((data & ~0xFF) | int3);

        if(ptrace(PTRACE_POKEDATA, m_process->pid(), m_address, dataWithInt3) < 0) {
            Error::sendErrno("Enabling BreakpointSite failed");
        }
    }

    m_isEnabled = true;
}

void BreakpointSite::disable()
{
    if(!m_isEnabled) {
        return;
    }

    if(m_isHardware) {
        m_process->clearHardwareBreakpoint(m_hardwareRegisterIndex);
        m_hardwareRegisterIndex = -1;
    } else {
        errno         = 0;
        uint64_t data = ptrace(PTRACE_PEEKDATA, m_process->pid(), m_address, nullptr);
        if(errno != 0) {
            Error::sendErrno("Enabling BreakpointSite failed");
        }

        auto restoredData = ((data & ~0xFF) | static_cast<uint8_t>(m_savedData));
        if(ptrace(PTRACE_POKEDATA, m_process->pid(), m_address, restoredData) < 0) {
            Error::sendErrno("Enabling BreakpointSite failed");
        }
    }

    m_isEnabled = false;
}

} // namespace pdb

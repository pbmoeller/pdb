#include <libpdb/error.hpp>
#include <libpdb/process.hpp>
#include <libpdb/watchpoint.hpp>

#include <utility>

namespace pdb {

namespace {

auto getNextId()
{
    static pdb::Watchpoint::IdType id = 0;
    return ++id;
}

} // namespace

void Watchpoint::enable() 
{ 
    if(m_isEnabled) {
        return;
    }

    hardwareRegisterIndex = m_process->setWatchpoint(m_id, m_address, m_mode, m_size);
    m_isEnabled = true;
}

void Watchpoint::disable() 
{ 
    if(!m_isEnabled) {
        return;
    }

    m_process->clearHardwareStoppoint(hardwareRegisterIndex);
    m_isEnabled = false;
}

void Watchpoint::updateData()
{
    uint64_t newData{0};
    auto read = m_process->readMemory(m_address, m_size);
    memcpy(&newData, read.data(), m_size);
    m_previousData = std::exchange(m_data, newData);
}

Watchpoint::Watchpoint(Process& proc, VirtAddr address, StoppointMode mode, size_t size)
    : m_process{&proc}
    , m_address{address}
    , m_isEnabled{false}
    , m_mode{mode}
    , m_size{size}
{
    if((address.addr() & (size - 1)) != 0) {
        Error::send("Watchpoint must be aligned to size");
    }

    m_id = getNextId();

    updateData();
}

} // namespace pdb

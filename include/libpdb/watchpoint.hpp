#ifndef LIBPDB_WATCHPOINT_HPP
#define LIBPDB_WATCHPOINT_HPP

#include <libpdb/types.hpp>

#include <cstddef>
#include <cstdint>

namespace pdb {

class Process;

class Watchpoint
{
public:
    Watchpoint()                            = delete;
    Watchpoint(const Watchpoint&)           = delete;
    Watchpoint& operator=(const Watchpoint&) = delete;

    using IdType = int32_t;
    IdType id() const { return m_id; }

    void enable();
    void disable();

    bool isEnabled() const { return m_isEnabled; }
    VirtAddr address() const { return m_address; }
    StoppointMode mode() const { return m_mode; }
    size_t size() const { return m_size; }

    bool atAddress(VirtAddr address) {
        return m_address == address;
    }
    bool inRange(VirtAddr low, VirtAddr high) {
        return low <= m_address && high > m_address;
    }

    uint64_t data() const { return m_data; }
    uint64_t previousData() const { return m_previousData; }

    void updateData();

private:
    friend Process;
    Watchpoint(Process& proc, VirtAddr address, StoppointMode mode, size_t size);

    IdType m_id;
    Process* m_process;
    VirtAddr m_address;
    StoppointMode m_mode;
    size_t m_size;
    bool m_isEnabled;
    int hardwareRegisterIndex{-1};
    uint64_t m_data{0};
    uint64_t m_previousData{0};
};

} // namespace pdb

#endif // LIBPDB_WATCHPOINT_HPP

#ifndef LIBPDB_BREAKPOINT_HPP
#define LIBPDB_BREAKPOINT_HPP

#include <libpdb/breakpoint_site.hpp>
#include <libpdb/stoppoint_collection.hpp>
#include <libpdb/types.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace pdb {

class Target;

class Breakpoint
{
public:
    virtual ~Breakpoint() = default;

    Breakpoint()                             = delete;
    Breakpoint(const Breakpoint&)            = delete;
    Breakpoint& operator=(const Breakpoint&) = delete;

    using IdType = std::uint32_t;
    IdType id() const { return m_id; }

    void enable();
    void disable();

    bool isEnabled() const { return m_isEnabled; }
    bool isHardware() const { return m_isHardware; }
    bool isInternal() const { return m_isInternal; }

    virtual void resolve() = 0;

    StoppointCollection<BreakpointSite, false>& breakpointSites() { return m_breakpointSites; }
    const StoppointCollection<BreakpointSite, false>& breakpointSites() const
    {
        return m_breakpointSites;
    }

    bool atAddress(VirtAddr addr) const { return m_breakpointSites.containsAddress(addr); }
    bool inRange(VirtAddr low, VirtAddr high) const
    {
        return !m_breakpointSites.getInRegion(low, high).empty();
    }

protected:
    friend Target;
    Breakpoint(Target& target, bool isHardware = false, bool isInternal = false);

protected:
    IdType m_id;
    Target* m_target;
    bool m_isEnabled{false};
    bool m_isHardware{false};
    bool m_isInternal{false};
    StoppointCollection<BreakpointSite, false> m_breakpointSites;
    BreakpointSite::IdType m_nextSiteId = 1;
};

class FunctionBreakpoint : public Breakpoint
{
public:
    void resolve() override;
    std::string_view functionName() const { return m_functionName; }

private:
    friend Target;
    FunctionBreakpoint(Target& target, std::string functionName, bool isHardware = false,
                       bool isInternal = false)
        : Breakpoint(target, isHardware, isInternal)
        , m_functionName(std::move(functionName))
    {
        resolve();
    }

private:
    std::string m_functionName;
};

class LineBreakpoint : public Breakpoint
{
public:
    void resolve() override;
    const std::filesystem::path file() const { return m_file; }
    size_t line() const { return m_line; }

private:
    friend Target;
    LineBreakpoint(Target& target, std::filesystem::path file, size_t line, bool isHardware = false,
                   bool isInternal = false)
        : Breakpoint(target, isHardware, isInternal)
        , m_file(std::move(file))
        , m_line(line)
    {
        resolve();
    }

private:
    std::filesystem::path m_file;
    size_t m_line;
};

class AddressBreakpoint : public Breakpoint
{
public:
    void resolve() override;
    VirtAddr address() const { return m_address; }

private:
    friend Target;
    AddressBreakpoint(Target& target, VirtAddr address, bool isHardware = false,
                      bool isInternal = false)
        : Breakpoint(target, isHardware, isInternal)
        , m_address(address)
    {
        resolve();
    }

private:
    VirtAddr m_address;
};

} // namespace pdb

#endif // LIBPDB_BREAKPOINT_HPP

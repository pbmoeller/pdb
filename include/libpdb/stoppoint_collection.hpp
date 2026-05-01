#ifndef LIBPDB_STOPPOINT_COLLECTION_HPP
#define LIBPDB_STOPPOINT_COLLECTION_HPP

#include <libpdb/error.hpp>
#include <libpdb/types.hpp>

#include <algorithm>
#include <memory>
#include <type_traits>
#include <vector>

namespace pdb {

template<typename Stoppoint, bool Owning = true>
class StoppointCollection
{
public:
    using PointerType = std::conditional_t<Owning, std::unique_ptr<Stoppoint>, Stoppoint*>;

public:
    Stoppoint& push(PointerType stoppoint)
    {
        m_stoppoints.push_back(std::move(stoppoint));
        return *m_stoppoints.back();
    }

    bool containsId(typename Stoppoint::IdType id) const;
    bool containsAddress(VirtAddr address) const;
    bool enabledStoppointAtAddress(VirtAddr address) const;

    Stoppoint& getById(typename Stoppoint::IdType id);
    const Stoppoint& getById(typename Stoppoint::IdType id) const;
    Stoppoint& getByAddress(VirtAddr address);
    const Stoppoint& getByAddress(VirtAddr address) const;

    std::vector<Stoppoint*> getInRegion(VirtAddr low, VirtAddr high) const;

    void removeById(typename Stoppoint::IdType id);
    void removeByAddress(VirtAddr address);

    template<typename Function>
    void forEach(Function f);
    template<typename Function>
    void forEach(Function f) const;

    size_t size() const { return m_stoppoints.size(); }
    bool empty() const { return m_stoppoints.empty(); }

private:
    using Points_t = std::vector<PointerType>;

    typename Points_t::iterator findById(typename Stoppoint::IdType id);
    typename Points_t::const_iterator findById(typename Stoppoint::IdType id) const;
    typename Points_t::iterator findByAddress(VirtAddr address);
    typename Points_t::const_iterator findByAddress(VirtAddr address) const;

private:
    Points_t m_stoppoints;
};

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::containsId(typename Stoppoint::IdType id) const -> bool
{
    return findById(id) != std::end(m_stoppoints);
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::containsAddress(VirtAddr address) const -> bool
{
    return findByAddress(address) != std::end(m_stoppoints);
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::enabledStoppointAtAddress(VirtAddr address) const
    -> bool
{
    return containsAddress(address) && getByAddress(address).isEnabled();
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::getById(typename Stoppoint::IdType id) -> Stoppoint&
{
    auto it = findById(id);
    if(it == std::end(m_stoppoints)) {
        Error::send("Invalid stop point");
    }
    return **it;
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::getById(typename Stoppoint::IdType id) const
    -> const Stoppoint&
{
    return const_cast<StoppointCollection<Stoppoint>*>(this)->getById(id);
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::getByAddress(VirtAddr address) -> Stoppoint&
{
    auto it = findByAddress(address);
    if(it == std::end(m_stoppoints)) {
        Error::send("Stop point with given address not found");
    }
    return **it;
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::getByAddress(VirtAddr address) const
    -> const Stoppoint&
{
    return const_cast<StoppointCollection<Stoppoint>*>(this)->getByAddress(address);
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::getInRegion(VirtAddr low, VirtAddr high) const
    -> std::vector<Stoppoint*>
{
    std::vector<Stoppoint*> ret;
    for(auto& site : m_stoppoints) {
        if(site->inRange(low, high)) {
            ret.push_back(&*site);
        }
    }
    return ret;
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::removeById(typename Stoppoint::IdType id) -> void
{
    auto it = findById(id);
    (**it).disable();
    m_stoppoints.erase(it);
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::removeByAddress(VirtAddr address) -> void
{
    auto it = findByAddress(address);
    (**it).disable();
    m_stoppoints.erase(it);
}

template<typename Stoppoint, bool Owning>
template<typename Function>
auto StoppointCollection<Stoppoint, Owning>::forEach(Function f) -> void
{
    for(auto& point : m_stoppoints) {
        f(*point);
    }
}

template<typename Stoppoint, bool Owning>
template<typename Function>
auto StoppointCollection<Stoppoint, Owning>::forEach(Function f) const -> void
{
    for(const auto& point : m_stoppoints) {
        f(*point);
    }
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::findById(typename Stoppoint::IdType id) ->
    typename Points_t::iterator
{
    return std::find_if(std::begin(m_stoppoints), std::end(m_stoppoints),
                        [=](auto& point) { return point->id() == id; });
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::findById(typename Stoppoint::IdType id) const ->
    typename Points_t::const_iterator
{
    return const_cast<StoppointCollection*>(this)->findById(id);
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::findByAddress(VirtAddr address) ->
    typename Points_t::iterator
{
    return std::find_if(std::begin(m_stoppoints), std::end(m_stoppoints),
                        [=](auto& point) { return point->atAddress(address); });
}

template<typename Stoppoint, bool Owning>
auto StoppointCollection<Stoppoint, Owning>::findByAddress(VirtAddr address) const ->
    typename Points_t::const_iterator
{
    return const_cast<StoppointCollection*>(this)->findByAddress(address);
}

} // namespace pdb

#endif // LIBPDB_STOPPOINT_COLLECTION_HPP

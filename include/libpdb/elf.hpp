#ifndef LIBPDB_ELF_HPP
#define LIBPDB_ELF_HPP

#include <libpdb/elf.hpp>
#include <libpdb/types.hpp>

#include <elf.h>

#include <filesystem>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

namespace pdb {

class Dwarf;

class Elf
{
public:
    Elf(const std::filesystem::path& path);
    ~Elf();

    Elf(const Elf&)            = delete;
    Elf& operator=(const Elf&) = delete;

    std::filesystem::path path() const { return m_path; }
    const Elf64_Ehdr& header() const { return m_header; }

    std::string_view getSectionName(size_t index) const;
    std::optional<const Elf64_Shdr*> getSection(std::string_view name) const;
    Span<const std::byte> getSectionContents(std::string_view name) const;

    std::string_view getString(std::size_t index) const;

    VirtAddr loadBias() const { return m_loadBias; }

    void notifyLoaded(VirtAddr address) { m_loadBias = address; }

    const Elf64_Shdr* getSectionContainingAddress(FileAddr addr) const;
    const Elf64_Shdr* getSectionContainingAddress(VirtAddr addr) const;
    std::optional<FileAddr> getSectionStartAddress(std::string_view name) const;

    std::vector<const Elf64_Sym*> getSymbolsByName(std::string_view name) const;
    std::optional<const Elf64_Sym*> getSymbolAtAddress(FileAddr addr) const;
    std::optional<const Elf64_Sym*> getSymbolAtAddress(VirtAddr addr) const;

    std::optional<const Elf64_Sym*> getSymbolContainingAddress(FileAddr addr) const;
    std::optional<const Elf64_Sym*> getSymbolContainingAddress(VirtAddr addr) const;

    Dwarf& getDwarf() { return *m_dwarf; }
    const Dwarf& getDwarf() const { return *m_dwarf; }

private:
    void parseSectionHeaders();
    void buildSectionMap();
    void parseSymbolTable();
    void buildSymbolMaps();

private:
    struct RangeComparator
    {
        bool operator()(std::pair<FileAddr, FileAddr> lhs, std::pair<FileAddr, FileAddr> rhs) const
        {
            return lhs.first < rhs.first;
        }
    };

private:
    int m_fd;
    std::filesystem::path m_path;
    std::size_t m_fileSize;
    std::byte* m_data;
    Elf64_Ehdr m_header;
    std::vector<Elf64_Shdr> m_sectionHeaders;
    std::unordered_map<std::string_view, Elf64_Shdr*> m_sectionMap;
    VirtAddr m_loadBias;
    std::vector<Elf64_Sym> m_symbolTable;
    std::unordered_multimap<std::string_view, Elf64_Sym*> m_symbolNameMap;
    std::map<std::pair<FileAddr, FileAddr>, Elf64_Sym*, RangeComparator> m_symbolAddrMap;
    std::unique_ptr<Dwarf> m_dwarf;
};

} // namespace pdb

#endif // LIBPDB_ELF_HPP

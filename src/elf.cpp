#include <libpdb/bit.hpp>
#include <libpdb/elf.hpp>
#include <libpdb/error.hpp>

#include <cxxabi.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>

namespace pdb {

Elf::Elf(const std::filesystem::path& path)
    : m_path(path)
{
    if((m_fd = open(path.c_str(), O_RDONLY)) < 0) {
        Error::sendErrno("Could not open ELF file");
    }

    struct stat stats;
    if(fstat(m_fd, &stats) < 0) {
        Error::sendErrno("Could not retrieve ELF file stats");
    }

    m_fileSize = stats.st_size;

    void* ret;
    if((ret = mmap(0, m_fileSize, PROT_READ, MAP_SHARED, m_fd, 0)) == MAP_FAILED) {
        close(m_fd);
        Error::sendErrno("Could not mmap ELF file");
    }
    m_data = reinterpret_cast<std::byte*>(ret);

    std::copy(m_data, m_data + sizeof(m_header), asBytes(m_header));

    parseSectionHeaders();
    buildSectionMap();
    parseSymbolTable();
    buildSymbolMaps();
}

Elf::~Elf()
{
    munmap(m_data, m_fileSize);
    close(m_fd);
}

std::string_view Elf::getSectionName(size_t index) const
{
    auto& section = m_sectionHeaders[m_header.e_shstrndx];
    return {reinterpret_cast<char*>(m_data) + section.sh_offset + index};
}

std::optional<const Elf64_Shdr*> Elf::getSection(std::string_view name) const
{
    if(m_sectionMap.count(name) == 0) {
        return std::nullopt;
    }
    return m_sectionMap.at(name);
}

Span<const std::byte> Elf::getSectionContents(std::string_view name) const
{
    if(auto sect = getSection(name); sect) {
        return {m_data + sect.value()->sh_offset, sect.value()->sh_size};
    }
    return {};
}

std::string_view Elf::getString(std::size_t index) const
{
    auto opt_strtab = getSection(".strtab");
    if(!opt_strtab) {
        opt_strtab = getSection(".dynstr");
        if(!opt_strtab) {
            return "";
        }
    }
    return reinterpret_cast<char*>(m_data) + opt_strtab.value()->sh_offset + index;
}

const Elf64_Shdr* Elf::getSectionContainingAddress(FileAddr addr) const
{
    if(addr.elfFile() != this) {
        return nullptr;
    }
    for(auto& section : m_sectionHeaders) {
        if(section.sh_addr <= addr.addr() && section.sh_addr + section.sh_size > addr.addr()) {
            return &section;
        }
    }
    return nullptr;
}

const Elf64_Shdr* Elf::getSectionContainingAddress(VirtAddr addr) const
{
    for(auto& section : m_sectionHeaders) {
        if(m_loadBias + section.sh_addr <= addr
           && m_loadBias + section.sh_addr + section.sh_size > addr) {
            return &section;
        }
    }
    return nullptr;
}

std::optional<FileAddr> Elf::getSectionStartAddress(std::string_view name) const
{
    if(auto sect = getSection(name); sect) {
        return FileAddr{*this, sect.value()->sh_addr};
    }
    return std::nullopt;
}

void Elf::parseSectionHeaders()
{
    auto nHeaders = m_header.e_shnum;
    if(nHeaders == 0 && m_header.e_shentsize != 0) {
        nHeaders = fromBytes<Elf64_Shdr>(m_data + m_header.e_shoff).sh_size;
    }

    m_sectionHeaders.resize(nHeaders);
    std::copy(m_data + m_header.e_shoff, m_data + m_header.e_shoff + sizeof(Elf64_Shdr) * nHeaders,
              reinterpret_cast<std::byte*>(m_sectionHeaders.data()));
}

void Elf::buildSectionMap()
{
    for(auto& section : m_sectionHeaders) {
        m_sectionMap[getSectionName(section.sh_name)] = &section;
    }
}

void Elf::parseSymbolTable()
{
    auto optSymtab = getSection(".symtab");
    if(!optSymtab) {
        optSymtab = getSection(".dynsym");
        if(!optSymtab) {
            return;
        }
    }

    auto symtab = *optSymtab;
    m_symbolTable.resize(symtab->sh_size / symtab->sh_entsize);
    std::copy(m_data + symtab->sh_offset, m_data + symtab->sh_offset + symtab->sh_size,
              reinterpret_cast<std::byte*>(m_symbolTable.data()));
}

void Elf::buildSymbolMaps()
{
    for(auto& symbol : m_symbolTable) {
        auto mangledName = getString(symbol.st_name);
        int demangleStatus;
        auto demangledName =
            abi::__cxa_demangle(mangledName.data(), nullptr, nullptr, &demangleStatus);
        if(demangleStatus == 0) {
            m_symbolNameMap.insert({demangledName, &symbol});
            free(demangledName);
        }
        m_symbolNameMap.insert({mangledName, &symbol});

        if(symbol.st_value != 0 && symbol.st_name != 0
           && ELF64_ST_TYPE(symbol.st_info) != STT_TLS) {
            auto addrRange = std::pair(FileAddr{*this, symbol.st_value},
                                       FileAddr{*this, symbol.st_value + symbol.st_size});
            m_symbolAddrMap.insert({addrRange, &symbol});
        }
    }
}

std::vector<const Elf64_Sym*> Elf::getSymbolsByName(std::string_view name) const
{
    auto [begin, end] = m_symbolNameMap.equal_range(name);

    std::vector<const Elf64_Sym*> ret;
    std::transform(begin, end, std::back_inserter(ret), [](auto& pair) { return pair.second; });
    return ret;
}

std::optional<const Elf64_Sym*> Elf::getSymbolAtAddress(FileAddr addr) const
{
    if(addr.elfFile() != this) {
        return std::nullopt;
    }
    FileAddr nullAddr;
    auto it = m_symbolAddrMap.find({addr, nullAddr});
    if(it == std::end(m_symbolAddrMap)) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<const Elf64_Sym*> Elf::getSymbolAtAddress(VirtAddr addr) const
{
    return getSymbolAtAddress(addr.toFileAddr(*this));
}

std::optional<const Elf64_Sym*> Elf::getSymbolContainingAddress(FileAddr addr) const
{
    if(addr.elfFile() != this || m_symbolAddrMap.empty()) {
        std::nullopt;
    }

    FileAddr nullAddr;
    auto it = m_symbolAddrMap.lower_bound({addr, nullAddr});
    if(it != std::end(m_symbolAddrMap)) {
        if(auto [key, value] = *it; key.first == addr) {
            return value;
        }
    }

    if(it == std::begin(m_symbolAddrMap)) {
        return std::nullopt;
    }

    --it;
    if(auto [key, value] = *it; key.first < addr && key.second > addr) {
        return value;
    }
    return std::nullopt;
}

std::optional<const Elf64_Sym*> Elf::getSymbolContainingAddress(VirtAddr addr) const
{
    return getSymbolContainingAddress(addr.toFileAddr(*this));
}

} // namespace pdb

#ifndef LIBPDB_DWARF_HPP
#define LIBPDB_DWARF_HPP

#include <libpdb/detail/dwarf.hpp>

#include <filesystem>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

namespace pdb {

class Die;
class Dwarf;
class Elf;
class CompileUnit;

struct AttrSpec
{
    uint64_t attr;
    uint64_t form;
};

struct Abbrev
{
    uint64_t code;
    uint64_t tag;
    bool hasChildren;
    std::vector<AttrSpec> attrSpecs;
};

class RangeList
{
public:
    RangeList(const CompileUnit* cu, Span<const std::byte> data, FileAddr baseAddress)
        : m_cu(cu)
        , m_data(data)
        , m_baseAddress(baseAddress)
    { }

    struct Entry
    {
        FileAddr low;
        FileAddr high;

        bool contains(FileAddr addr) const { return low <= addr && addr < high; }
    };

    class Iterator;
    Iterator begin() const;
    Iterator end() const;

    bool contains(FileAddr address) const;

private:
    const CompileUnit* m_cu;
    Span<const std::byte> m_data;
    FileAddr m_baseAddress;
};

class RangeList::Iterator
{
public:
    using value_type        = Entry;
    using reference         = const Entry&;
    using pointer           = const Entry*;
    using difference_type   = std::ptrdiff_t;
    using iterator_category = std::forward_iterator_tag;

public:
    Iterator(const CompileUnit* cu, Span<const std::byte> data, FileAddr baseAddress);

    Iterator()                           = default;
    Iterator(const Iterator&)            = default;
    Iterator& operator=(const Iterator&) = default;

    const Entry& operator*() const { return m_current; }
    const Entry* operator->() const { return &m_current; }

    bool operator==(Iterator rhs) const { return m_pos == rhs.m_pos; }
    bool operator!=(Iterator rhs) const { return m_pos != rhs.m_pos; }

    Iterator& operator++();
    Iterator operator++(int);

private:
    const CompileUnit* m_cu{nullptr};
    Span<const std::byte> m_data{nullptr, nullptr};
    FileAddr m_baseAddress;
    const std::byte* m_pos{nullptr};
    Entry m_current;
};

class LineTable
{
public:
    struct File
    {
        std::filesystem::path path;
        uint64_t modificationTime;
        uint64_t fileLength;
    };

    struct Entry;

public:
    LineTable(Span<const std::byte> data, const CompileUnit* cu, bool defaultIsStmt,
              int8_t lineBase, uint8_t lineRange, uint8_t opcodeBase,
              std::vector<std::filesystem::path> includeDirectories, std::vector<File> fileNames)
        : m_data(data)
        , m_cu(cu)
        , m_defaultIsStmt(defaultIsStmt)
        , m_lineBase(lineBase)
        , m_lineRange(lineRange)
        , m_opcodeBase(opcodeBase)
        , m_includeDirectories(includeDirectories)
        , m_fileNames(fileNames)
    { }

    LineTable(const LineTable&)            = delete;
    LineTable& operator=(const LineTable&) = delete;

    const CompileUnit& cu() const { return *m_cu; }
    const std::vector<File>& fileNames() const { return m_fileNames; }

    class Iterator;
    Iterator begin() const;
    Iterator end() const;

    Iterator getEntryByAddress(FileAddr address) const;
    std::vector<Iterator> getEntriesByLine(std::filesystem::path path, size_t line) const;

private:
    Span<const std::byte> m_data;
    const CompileUnit* m_cu;
    bool m_defaultIsStmt;
    int8_t m_lineBase;
    uint8_t m_lineRange;
    uint8_t m_opcodeBase;
    std::vector<std::filesystem::path> m_includeDirectories;
    mutable std::vector<File> m_fileNames;
};

struct LineTable::Entry
{
    FileAddr address;
    uint64_t fileIndex{1};
    uint64_t line{1};
    uint64_t column{0};
    bool isStmt;
    bool basicBlockStart{false};
    bool endSequence{false};
    bool prologueEnd{false};
    bool epilogueBegin{false};
    uint64_t discriminator{0};
    File* fileEntry{nullptr};

    bool operator==(const Entry& rhs) const
    {
        return address == rhs.address && fileIndex == rhs.fileIndex && line == rhs.line
            && column == rhs.column && discriminator == rhs.discriminator;
    }
};

class LineTable::Iterator
{
public:
    using value_type        = Entry;
    using reference         = const Entry&;
    using pointer           = const Entry*;
    using difference_type   = std::ptrdiff_t;
    using iterator_category = std::forward_iterator_tag;

public:
    Iterator(const LineTable* table);

    Iterator()                           = default;
    Iterator(const Iterator&)            = default;
    Iterator& operator=(const Iterator&) = default;

    const LineTable::Entry& operator*() const { return m_current; }
    const LineTable::Entry* operator->() const { return &m_current; }

    bool operator==(const Iterator& rhs) const { return m_pos == rhs.m_pos; }
    bool operator!=(const Iterator& rhs) const { return m_pos != rhs.m_pos; }

    Iterator& operator++();
    Iterator operator++(int);

private:
    bool executeInstruction();

private:
    const LineTable* m_table;
    LineTable::Entry m_current;
    LineTable::Entry m_registers;
    const std::byte* m_pos;
};

class Attr
{
public:
    Attr(const CompileUnit* cu, uint64_t type, uint64_t form, const std::byte* location)
        : m_cu(cu)
        , m_type(type)
        , m_form(form)
        , m_location(location)
    { }

    uint64_t name() const { return m_type; }
    uint64_t form() const { return m_form; }

    FileAddr asAddress() const;
    uint32_t asSectionOffset() const;
    Span<const std::byte> asBlock() const;
    uint64_t asInt() const;
    std::string_view asString() const;
    Die asReference() const;

    RangeList asRangeList() const;

private:
    const CompileUnit* m_cu;
    uint64_t m_type;
    uint64_t m_form;
    const std::byte* m_location;
};

class CompileUnit
{
public:
    CompileUnit(Dwarf& parent, Span<const std::byte> data, size_t abbrevOffset);

    const Dwarf* dwarfInfo() const { return m_parent; }
    Span<const std::byte> data() const { return m_data; }

    const std::unordered_map<uint64_t, Abbrev>& abbrevTable() const;

    Die root() const;

    const LineTable& lines() const { return *m_lineTable; }

private:
    Dwarf* m_parent;
    Span<const std::byte> m_data;
    size_t m_abbrevOffset;
    std::unique_ptr<LineTable> m_lineTable;
};

struct SourceLocation
{
    const LineTable::File *file;
    uint64_t line;
};

class Die
{
public:
    explicit Die(const std::byte* next)
        : m_next(next)
    { }
    Die(const std::byte* pos, const CompileUnit* cu, const Abbrev* abbrev,
        std::vector<const std::byte*> attrLocs, const std::byte* next)
        : m_pos(pos)
        , m_cu(cu)
        , m_abbrev(abbrev)
        , m_attrLocs(std::move(attrLocs))
        , m_next(next)
    { }

    class ChildrenRange;
    ChildrenRange children() const;

    const CompileUnit* cu() const { return m_cu; }
    const Abbrev* abbrevEntry() const { return m_abbrev; }
    const std::byte* position() const { return m_pos; }
    const std::byte* next() const { return m_next; }

    bool contains(uint64_t attribute) const;
    Attr operator[](uint64_t attribute) const;

    FileAddr lowPc() const;
    FileAddr highPc() const;

    bool containsAddress(FileAddr address) const;

    std::optional<std::string_view> name() const;

    SourceLocation location() const;
    const LineTable::File& file() const;
    uint64_t line() const;

private:
    const std::byte* m_pos{nullptr};
    const CompileUnit* m_cu{nullptr};
    const Abbrev* m_abbrev{nullptr};
    const std::byte* m_next{nullptr};
    std::vector<const std::byte*> m_attrLocs;
};

class Die::ChildrenRange
{
public:
    ChildrenRange(Die die)
        : m_die(std::move(die))
    { }

    class Iterator
    {
    public:
        using value_type        = Die;
        using reference         = const Die&;
        using pointer           = const Die*;
        using difference_ytpe   = std::ptrdiff_t;
        using iterator_category = std::forward_iterator_tag;

        Iterator()                           = default;
        Iterator(const Iterator&)            = default;
        Iterator& operator=(const Iterator&) = default;

        explicit Iterator(const Die& die);

        const Die& operator*() const { return *m_die; }
        const Die* operator->() const { return &m_die.value(); }

        Iterator operator++();
        Iterator operator++(int);

        bool operator==(const Iterator& rhs) const;
        bool operator!=(const Iterator& rhs) const { return !(*this == rhs); }

    private:
        std::optional<Die> m_die;
    };

    Iterator begin() const
    {
        if(m_die.m_abbrev->hasChildren) {
            return Iterator(m_die);
        }
        return end();
    }

    Iterator end() const { return Iterator{}; }

private:
    Die m_die;
};

class Dwarf
{
public:
    Dwarf(const Elf& parent);
    const Elf* elfFile() const { return m_elf; }

    const std::unordered_map<std::uint64_t, Abbrev>& getAbbrevTable(size_t offset);

    const std::vector<std::unique_ptr<CompileUnit>>& compileUnits() const { return m_compileUnits; }

    const CompileUnit* compileUnitContainingAddress(FileAddr address) const;
    std::optional<Die> functionContainingAddress(FileAddr address) const;

    std::vector<Die> findFunctions(std::string name) const;

    LineTable::Iterator lineEntryAtAddress(FileAddr address) const;

private:
    void index() const;
    void indexDie(const Die& current) const;

private:
    const Elf* m_elf;

    std::unordered_map<size_t, std::unordered_map<std::uint64_t, Abbrev>> m_abbrevTables;
    std::vector<std::unique_ptr<CompileUnit>> m_compileUnits;

    struct IndexEntry
    {
        const CompileUnit* cu;
        const std::byte* pos;
    };
    mutable std::unordered_multimap<std::string, IndexEntry> m_functionIndex;
};

} // namespace pdb

#endif // LIBPDB_DWARF_HPP

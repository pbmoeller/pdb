#include <libpdb/bit.hpp>
#include <libpdb/dwarf.hpp>
#include <libpdb/elf.hpp>
#include <libpdb/error.hpp>
#include <libpdb/types.hpp>

#include <algorithm>
#include <string_view>

namespace pdb {

namespace {

class Cursor
{
public:
    explicit Cursor(Span<const std::byte> data)
        : m_data{data}
        , m_pos{data.begin()}
    { }

    Cursor& operator++()
    {
        ++m_pos;
        return *this;
    }
    Cursor& operator+=(size_t size)
    {
        m_pos += size;
        return *this;
    }

    const std::byte* position() const { return m_pos; }
    bool finished() const { return m_pos >= m_data.end(); }

    template<typename T>
    T fixedInt()
    {
        auto t = pdb::fromBytes<T>(m_pos);
        m_pos += sizeof(T);
        return t;
    }

    uint8_t u8() { return fixedInt<uint8_t>(); }
    uint16_t u16() { return fixedInt<uint16_t>(); }
    uint32_t u32() { return fixedInt<uint32_t>(); }
    uint64_t u64() { return fixedInt<uint64_t>(); }
    int8_t s8() { return fixedInt<int8_t>(); }
    int16_t s16() { return fixedInt<int16_t>(); }
    int32_t s32() { return fixedInt<int32_t>(); }
    int64_t s64() { return fixedInt<int64_t>(); }

    std::string_view string()
    {
        auto nullTerminator = std::find(m_pos, m_data.end(), std::byte{0});
        std::string_view ret{reinterpret_cast<const char*>(m_pos),
                             static_cast<size_t>(nullTerminator - m_pos)};
        m_pos = nullTerminator + 1;
        return ret;
    }

    uint64_t uleb128()
    {
        uint64_t res = 0;
        int shift    = 0;
        uint8_t byte = 0;
        do {
            byte        = u8();
            auto masked = static_cast<uint64_t>(byte & 0x7F);
            res |= masked << shift;
            shift += 7;
        } while((byte & 0x80) != 0);

        return res;
    }

    int64_t sleb128()
    {
        int64_t res  = 0;
        int shift    = 0;
        uint8_t byte = 0;
        do {
            byte        = u8();
            auto masked = static_cast<uint64_t>(byte & 0x7F);
            res |= masked << shift;
            shift += 7;
        } while((byte & 0x80) != 0);

        if((shift < sizeof(res) * 8) && (byte & 0x40)) {
            res |= (~static_cast<uint64_t>(0) << shift);
        }

        return res;
    }

    void skipForm(uint64_t form)
    {
        switch(form) {
            case DW_FORM_flag_present:
                break;
            case DW_FORM_data1:
            case DW_FORM_ref1:
            case DW_FORM_flag:
                m_pos += 1;
                break;
            case DW_FORM_data2:
            case DW_FORM_ref2:
                m_pos += 2;
                break;
            case DW_FORM_data4:
            case DW_FORM_ref4:
            case DW_FORM_ref_addr:
            case DW_FORM_sec_offset:
            case DW_FORM_strp:
                m_pos += 4;
                break;
            case DW_FORM_data8:
            case DW_FORM_addr:
                m_pos += 8;
                break;
            case DW_FORM_sdata:
                sleb128();
                break;
            case DW_FORM_udata:
            case DW_FORM_ref_udata:
                uleb128();
                break;
            case DW_FORM_block1:
                m_pos += u8();
                break;
            case DW_FORM_block2:
                m_pos += u16();
                break;
            case DW_FORM_block4:
                m_pos += u32();
                break;
            case DW_FORM_block:
            case DW_FORM_exprloc:
                m_pos += uleb128();
                break;
            case DW_FORM_string:
                while(!finished() && *m_pos != std::byte(0)) {
                    ++m_pos;
                }
                ++m_pos;
                break;
            case DW_FORM_indirect:
                skipForm(uleb128());
                break;
            default:
                Error::send("Unrecognized DWARF form");
        }
    }

private:
    Span<const std::byte> m_data;
    const std::byte* m_pos;
};

std::unordered_map<uint64_t, Abbrev> parseAbbrevTable(const Elf& obj, size_t offset)
{
    Cursor cur(obj.getSectionContents(".debug_abbrev"));
    cur += offset;
    std::unordered_map<uint64_t, Abbrev> table;
    uint64_t code{0};
    do {
        code             = cur.uleb128();
        auto tag         = cur.uleb128();
        auto hasChildren = static_cast<bool>(cur.u8());

        std::vector<AttrSpec> attrSpecs;
        uint64_t attr{0};
        do {
            attr      = cur.uleb128();
            auto form = cur.uleb128();
            if(attr != 0) {
                attrSpecs.push_back(AttrSpec{attr, form});
            }
        } while(attr != 0);

        if(code != 0) {
            table.emplace(code, Abbrev{code, tag, hasChildren, std::move(attrSpecs)});
        }
    } while(code != 0);
    return table;
}

std::unique_ptr<CompileUnit> parseCompileUnit(Dwarf& dwarf, const Elf& obj, Cursor cur)
{
    auto start       = cur.position();
    auto size        = cur.u32();
    auto version     = cur.u16();
    auto abbrev      = cur.u32();
    auto addressSize = cur.u8();

    if(size == 0xFFFFFFFF) {
        Error::send("Only DWARF32 is supported");
    }
    if(version != 4) {
        Error::send("Only DWARF version 4 is supported");
    }
    if(addressSize != 8) {
        Error::send("Invalid address size for DWARF");
    }
    size += sizeof(uint32_t);
    Span<const std::byte> data{start, size};
    return std::make_unique<CompileUnit>(dwarf, data, abbrev);
}

std::vector<std::unique_ptr<CompileUnit>> parseCompileUnits(Dwarf& dwarf, const Elf& obj)
{
    auto debugInfo = obj.getSectionContents(".debug_info");
    Cursor cur(debugInfo);

    std::vector<std::unique_ptr<CompileUnit>> units;
    while(!cur.finished()) {
        auto unit = parseCompileUnit(dwarf, obj, cur);
        cur += unit->data().size();
        units.push_back(std::move(unit));
    }

    return units;
}

Die parseDie(const CompileUnit& cu, Cursor cur)
{
    auto pos        = cur.position();
    auto abbrevCode = cur.uleb128();

    if(abbrevCode == 0) {
        auto next = cur.position();
        return Die(next);
    }

    auto& abbrevTable = cu.abbrevTable();
    auto& abbrev      = abbrevTable.at(abbrevCode);
    std::vector<const std::byte*> attrLocs;
    attrLocs.reserve(abbrev.attrSpecs.size());
    for(auto& attr : abbrev.attrSpecs) {
        attrLocs.push_back(cur.position());
        cur.skipForm(attr.form);
    }

    auto next = cur.position();
    return Die(pos, &cu, &abbrev, std::move(attrLocs), next);
}

LineTable::File parseLineTableFile(Cursor& cur, std::filesystem::path compilationDir,
                                   const std::vector<std::filesystem::path>& includeDirectories)
{
    auto file             = cur.string();
    auto dirIndex         = cur.uleb128();
    auto modificationTime = cur.uleb128();
    auto fileLength       = cur.uleb128();

    std::filesystem::path path = file;
    if(file[0] != '/') {
        if(dirIndex == 0) {
            path = compilationDir / std::string(file);
        } else {
            path = includeDirectories[dirIndex - 1] / std::string(file);
        }
    }
    return {path.string(), modificationTime, fileLength};
}

std::unique_ptr<LineTable> parseLineTable(const CompileUnit& cu)
{
    auto section = cu.dwarfInfo()->elfFile()->getSectionContents(".debug_line");
    if(!cu.root().contains(DW_AT_stmt_list)) {
        return nullptr;
    }
    auto offset = cu.root()[DW_AT_stmt_list].asSectionOffset();
    Cursor cur({section.begin() + offset, section.end()});

    auto size = cur.u32();
    auto end  = cur.position() + size;

    auto version = cur.u16();
    if(version != 4) {
        Error::send("Only DWARF 4 is supported");
    }

    (void)cur.u32();

    auto minimumInstructionLength = cur.u8();
    if(minimumInstructionLength != 1) {
        Error::send("Invalid minimum instruction length");
    }

    auto maximumOperationsPerInstruction = cur.u8();
    if(maximumOperationsPerInstruction != 1) {
        Error::send("Invalid maximum operations per instruction");
    }

    auto defaultIsStmt = cur.u8();
    auto lineBase      = cur.s8();
    auto lineRange     = cur.u8();
    auto opcodeBase    = cur.u8();

    std::array<uint8_t, 12> expectedOpcodeLentghs{0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1};
    for(auto i = 0; i < opcodeBase - 1; ++i) {
        if(cur.u8() != expectedOpcodeLentghs[i]) {
            Error::send("Unexpected opcode length");
        }
    }

    std::vector<std::filesystem::path> includeDirectories;
    std::filesystem::path compilationDir(cu.root()[DW_AT_comp_dir].asString());
    for(auto dir = cur.string(); !dir.empty(); dir = cur.string()) {
        if(dir[0] == '/') {
            includeDirectories.push_back(std::string(dir));
        } else {
            includeDirectories.push_back(compilationDir / std::string(dir));
        }
    }

    std::vector<LineTable::File> fileNames;
    while(*cur.position() != std::byte(0)) {
        fileNames.push_back(parseLineTableFile(cur, compilationDir, includeDirectories));
    }
    cur += 1;

    Span<const std::byte> data{cur.position(), end};
    return std::make_unique<LineTable>(data, &cu, defaultIsStmt, lineBase, lineRange, opcodeBase,
                                       std::move(includeDirectories), std::move(fileNames));
}

bool pathEndsIn(const std::filesystem::path& lhs, const std::filesystem::path& rhs)
{
    auto lhsSize = std::distance(lhs.begin(), lhs.end());
    auto rhsSize = std::distance(rhs.begin(), rhs.end());
    if(rhsSize > lhsSize) {
        return false;
    }
    auto start = std::next(lhs.begin(), lhsSize - rhsSize);
    return std::equal(start, lhs.end(), rhs.begin());
}

} // namespace

// RangeList

RangeList::Iterator RangeList::begin() const
{
    return {m_cu, m_data, m_baseAddress};
}

RangeList::Iterator RangeList::end() const
{
    return {};
}

bool RangeList::contains(FileAddr address) const
{
    return std::any_of(begin(), end(), [=](auto& e) { return e.contains(address); });
}

// RangeList::Iterator

RangeList::Iterator::Iterator(const CompileUnit* cu, Span<const std::byte> data,
                              FileAddr baseAddress)
    : m_cu(cu)
    , m_data(data)
    , m_baseAddress(baseAddress)
    , m_pos(data.begin())
{
    ++(*this);
}

RangeList::Iterator& RangeList::Iterator::operator++()
{
    auto elf                       = m_cu->dwarfInfo()->elfFile();
    constexpr auto baseAddressFlag = ~static_cast<uint64_t>(0);

    Cursor cur({m_pos, m_data.end()});
    while(true) {
        m_current.low  = FileAddr{*elf, cur.u64()};
        m_current.high = FileAddr{*elf, cur.u64()};

        if(m_current.low.addr() == baseAddressFlag) {
            m_baseAddress = m_current.high;
        } else if(m_current.low.addr() == 0 && m_current.high.addr() == 0) {
            m_pos = nullptr;
            break;
        } else {
            m_pos = cur.position();
            m_current.low += m_baseAddress.addr();
            m_current.high += m_baseAddress.addr();
            break;
        }
    }
    return *this;
}

RangeList::Iterator RangeList::Iterator::operator++(int)
{
    auto tmp = *this;
    ++(*this);
    return tmp;
}

// LineTable

LineTable::Iterator LineTable::begin() const
{
    return Iterator(this);
}

LineTable::Iterator LineTable::end() const
{
    return {};
}

LineTable::Iterator LineTable::getEntryByAddress(FileAddr address) const
{
    auto prev = begin();
    if(prev == end()) {
        return prev;
    }

    auto it = prev;
    for(++it; it != end(); prev = it++) {
        if(prev->address <= address && it->address > address && !prev->endSequence) {
            return prev;
        }
    }
    return end();
}

std::vector<LineTable::Iterator> LineTable::getEntriesByLine(std::filesystem::path path,
                                                             size_t line) const
{
    std::vector<Iterator> entries;
    for(auto it = begin(); it != end(); ++it) {
        auto& entryPath = it->fileEntry->path;
        if(it->line == line) {
            if((path.is_absolute() && entryPath == path)
               || (path.is_relative() && pathEndsIn(entryPath, path))) {
                entries.push_back(it);
            }
        }
    }
    return entries;
}

// LineTable::Iterator

LineTable::Iterator::Iterator(const LineTable* table)
    : m_table(table)
    , m_pos(table->m_data.begin())
{
    m_registers.isStmt = table->m_defaultIsStmt;
    ++(*this);
}

LineTable::Iterator& LineTable::Iterator::operator++()
{
    if(m_pos == m_table->m_data.end()) {
        m_pos = nullptr;
        return *this;
    }

    bool emitted = false;
    do {
        emitted = executeInstruction();
    } while(!emitted);

    m_current.fileEntry = &m_table->m_fileNames[m_current.fileIndex - 1];
    return *this;
}

LineTable::Iterator LineTable::Iterator::operator++(int)
{
    auto tmp = *this;
    ++(*this);
    return tmp;
}

bool LineTable::Iterator::executeInstruction()
{
    auto elf = m_table->m_cu->dwarfInfo()->elfFile();
    Cursor cur({m_pos, m_table->m_data.end()});
    auto opcode  = cur.u8();
    bool emitted = false;

    if(opcode > 0 && opcode < m_table->m_opcodeBase) {
        switch(opcode) {
            case DW_LNS_copy:
                m_current                   = m_registers;
                m_registers.basicBlockStart = false;
                m_registers.prologueEnd     = false;
                m_registers.epilogueBegin   = false;
                m_registers.discriminator   = 0;
                emitted                     = true;
                break;
            case DW_LNS_advance_pc:
                m_registers.address += cur.uleb128();
                break;
            case DW_LNS_advance_line:
                m_registers.line += cur.sleb128();
                break;
            case DW_LNS_set_file:
                m_registers.fileIndex = cur.uleb128();
                break;
            case DW_LNS_set_column:
                m_registers.column = cur.uleb128();
                break;
            case DW_LNS_negate_stmt:
                m_registers.isStmt = !m_registers.isStmt;
                break;
            case DW_LNS_set_basic_block:
                m_registers.basicBlockStart = true;
                break;
            case DW_LNS_const_add_pc:
                m_registers.address += (255 - m_table->m_opcodeBase) / m_table->m_lineRange;
                break;
            case DW_LNS_fixed_advance_pc:
                m_registers.address += cur.u16();
                break;
            case DW_LNS_set_prologue_end:
                m_registers.prologueEnd = true;
                break;
            case DW_LNS_set_epilogue_begin:
                m_registers.epilogueBegin = true;
                break;
            case DW_LNS_set_isa:
                break;
            default:
                Error::send("Unexpected standard opcode");
        }
    } else if(opcode == 0) {
        auto length         = cur.uleb128();
        auto extendedOpcode = cur.u8();
        switch(extendedOpcode) {
            case DW_LNE_end_sequence:
                m_registers.endSequence = true;
                m_current               = m_registers;
                m_registers             = Entry{};
                m_registers.isStmt      = m_table->m_defaultIsStmt;
                emitted                 = true;
                break;
            case DW_LNE_set_address:
                m_registers.address = FileAddr(*elf, cur.u64());
                break;
            case DW_LNE_define_file:
            {
                auto compilationDir = m_table->m_cu->root()[DW_AT_comp_dir].asString();
                auto file           = parseLineTableFile(cur, std::string(compilationDir),
                                                         m_table->m_includeDirectories);
                m_table->m_fileNames.push_back(file);
                break;
            }
            case DW_LNE_set_discriminator:
                m_registers.discriminator = cur.uleb128();
                break;
            default:
                Error::send("Unexpected extended opcode");
                break;
        }
    } else {
        auto adjustedOpcode = opcode - m_table->m_opcodeBase;
        m_registers.address += adjustedOpcode / m_table->m_lineRange;
        m_registers.line += m_table->m_lineBase + (adjustedOpcode % m_table->m_lineRange);
        m_current                   = m_registers;
        m_registers.basicBlockStart = false;
        m_registers.prologueEnd     = false;
        m_registers.epilogueBegin   = false;
        m_registers.discriminator   = 0;
        emitted                     = true;
    }

    m_pos = cur.position();
    return emitted;
}

// Attr

FileAddr Attr::asAddress() const
{
    Cursor cur({m_location, m_cu->data().end()});
    if(m_form != DW_FORM_addr) {
        Error::send("Invalid address type");
    }
    auto elf = m_cu->dwarfInfo()->elfFile();
    return FileAddr{*elf, cur.u64()};
}

uint32_t Attr::asSectionOffset() const
{
    Cursor cur({m_location, m_cu->data().end()});
    if(m_form != DW_FORM_sec_offset) {
        Error::send("Invalid offset type");
    }
    return cur.u32();
}

Span<const std::byte> Attr::asBlock() const
{
    size_t size;
    Cursor cur({m_location, m_cu->data().end()});
    switch(m_form) {
        case DW_FORM_block1:
            size = cur.u8();
            break;
        case DW_FORM_block2:
            size = cur.u16();
            break;
        case DW_FORM_block4:
            size = cur.u32();
            break;
        case DW_FORM_block:
            size = cur.uleb128();
            break;
        default:
            Error::send("Invalid block type");
    }
    return {cur.position(), size};
}

uint64_t Attr::asInt() const
{
    Cursor cur({m_location, m_cu->data().end()});
    switch(m_form) {
        case DW_FORM_data1:
            return cur.u8();
        case DW_FORM_data2:
            return cur.u16();
        case DW_FORM_data4:
            return cur.u32();
        case DW_FORM_data8:
            return cur.u64();
        case DW_FORM_udata:
            return cur.uleb128();
        default:
            Error::send("Invalid integer type");
    }
}

std::string_view Attr::asString() const
{
    Cursor cur({m_location, m_cu->data().end()});
    switch(m_form) {
        case DW_FORM_string:
            return cur.string();
        case DW_FORM_strp:
        {
            auto offset = cur.u32();
            auto stab   = m_cu->dwarfInfo()->elfFile()->getSectionContents(".debug_str");
            Cursor stabCur({stab.begin() + offset, stab.end()});
            return stabCur.string();
        }
        default:
            Error::send("Invalid string type");
    }
}

Die Attr::asReference() const
{
    Cursor cur({m_location, m_cu->data().end()});
    size_t offset;
    switch(m_form) {
        case DW_FORM_ref1:
            offset = cur.u8();
            break;
        case DW_FORM_ref2:
            offset = cur.u16();
            break;
        case DW_FORM_ref4:
            offset = cur.u32();
            break;
        case DW_FORM_ref8:
            offset = cur.u64();
            break;
        case DW_FORM_ref_udata:
            offset = cur.uleb128();
            break;
        case DW_FORM_ref_addr:
        {
            offset        = cur.u32();
            auto section  = m_cu->dwarfInfo()->elfFile()->getSectionContents(".debug_info");
            auto diePos   = section.begin() + offset;
            auto& cus     = m_cu->dwarfInfo()->compileUnits();
            auto cuFinder = [=](auto& cu) {
                return cu->data().begin() <= diePos && cu->data().end() > diePos;
            };
            auto cuForOffset = std::find_if(std::begin(cus), std::end(cus), cuFinder);
            Cursor refCur({diePos, cuForOffset->get()->data().end()});
            return parseDie(**cuForOffset, refCur);
        }
        default:
            Error::send("Invalid reference type");
    }

    Cursor refCur({m_cu->data().begin() + offset, m_cu->data().end()});

    return parseDie(*m_cu, refCur);
}

RangeList Attr::asRangeList() const
{
    auto section = m_cu->dwarfInfo()->elfFile()->getSectionContents(".debug_ranges");
    auto offset  = asSectionOffset();

    Span<const std::byte> data(section.begin() + offset, section.end());

    auto root = m_cu->root();
    FileAddr baseAddress =
        root.contains(DW_AT_low_pc) ? root[DW_AT_low_pc].asAddress() : FileAddr{};

    return {m_cu, data, baseAddress};
}

// CompileUnit

CompileUnit::CompileUnit(Dwarf& parent, Span<const std::byte> data, size_t abbrevOffset)
    : m_parent(&parent)
    , m_data(data)
    , m_abbrevOffset(abbrevOffset)
{
    m_lineTable = parseLineTable(*this);
}

const std::unordered_map<uint64_t, Abbrev>& CompileUnit::abbrevTable() const
{
    return m_parent->getAbbrevTable(m_abbrevOffset);
}

Die CompileUnit::root() const
{
    std::size_t headerSize = 11;
    Cursor cur({m_data.begin() + headerSize, m_data.end()});
    return parseDie(*this, cur);
}

// Die::ChildrenRange

Die::ChildrenRange Die::children() const
{
    return ChildrenRange(*this);
}

bool Die::contains(uint64_t attribute) const
{
    auto& specs = m_abbrev->attrSpecs;
    return std::find_if(std::begin(specs), std::end(specs),
                        [=](auto spec) { return spec.attr == attribute; })
        != std::end(specs);
}

Attr Die::operator[](uint64_t attribute) const
{
    auto& specs = m_abbrev->attrSpecs;
    for(size_t i = 0; i < specs.size(); ++i) {
        if(specs[i].attr == attribute) {
            return {m_cu, specs[i].attr, specs[i].form, m_attrLocs[i]};
        }
    }
    Error::send("Attribute not found!");
}

FileAddr Die::lowPc() const
{
    if(contains(DW_AT_ranges)) {
        auto firstEntry = (*this)[DW_AT_ranges].asRangeList().begin();
        return firstEntry->low;
    } else if(contains(DW_AT_low_pc)) {
        return (*this)[DW_AT_low_pc].asAddress();
    }

    Error::send("DIE does not have low PC");
}

FileAddr Die::highPc() const
{
    if(contains(DW_AT_ranges)) {
        auto ranges = (*this)[DW_AT_ranges].asRangeList();
        auto it     = ranges.begin();
        while(std::next(it) != ranges.end()) {
            ++it;
        }
        return it->high;
    } else if(contains(DW_AT_high_pc)) {
        auto attr = (*this)[DW_AT_high_pc];
        FileAddr addr;
        if(attr.form() == DW_FORM_addr) {
            return attr.asAddress();
        } else {
            return lowPc() + attr.asInt();
        }
    }

    Error::send("DIE does not have high PC");
}

bool Die::containsAddress(FileAddr address) const
{
    if(address.elfFile() != this->m_cu->dwarfInfo()->elfFile()) {
        return false;
    }

    if(contains(DW_AT_ranges)) {
        return (*this)[DW_AT_ranges].asRangeList().contains(address);
    } else if(contains(DW_AT_low_pc)) {
        return lowPc() <= address && highPc() > address;
    }
    return false;
}

std::optional<std::string_view> Die::name() const
{
    if(contains(DW_AT_name)) {
        return (*this)[DW_AT_name].asString();
    }
    if(contains(DW_AT_specification)) {
        return (*this)[DW_AT_specification].asReference().name();
    }
    if(contains(DW_AT_abstract_origin)) {
        return (*this)[DW_AT_abstract_origin].asReference().name();
    }
    return std::nullopt;
}

SourceLocation Die::location() const
{
    return {&file(), line()};
}

const LineTable::File& Die::file() const
{
    uint64_t idx;
    if(m_abbrev->tag == DW_TAG_inlined_subroutine) {
        idx = (*this)[DW_AT_call_file].asInt();
    } else {
        idx = (*this)[DW_AT_decl_file].asInt();
    }
    return this->m_cu->lines().fileNames()[idx - 1];
}

uint64_t Die::line() const
{
    if(m_abbrev->tag == DW_TAG_inlined_subroutine) {
        return (*this)[DW_AT_call_line].asInt();
    }
    return (*this)[DW_AT_decl_line].asInt();
}

// Die::ChildrenRange::Iterator

Die::ChildrenRange::Iterator::Iterator(const Die& die)
{
    Cursor nextCur({die.m_next, die.m_cu->data().end()});
    m_die = parseDie(*die.m_cu, nextCur);
}

Die::ChildrenRange::Iterator Die::ChildrenRange::Iterator::operator++()
{
    if(!m_die.has_value() || !m_die->m_abbrev) {
        return *this;
    }
    if(!m_die->m_abbrev->hasChildren) {
        Cursor nextCur({m_die->m_next, m_die->m_cu->data().end()});
        m_die = parseDie(*m_die->m_cu, nextCur);
    } else if(m_die->contains(DW_AT_sibling)) {
        m_die = m_die.value()[DW_AT_sibling].asReference();
    } else {
        Iterator subChildren(*m_die);
        while(subChildren->m_abbrev) {
            ++subChildren;
        }
        Cursor nextCur({subChildren->m_next, m_die->m_cu->data().end()});
        m_die = parseDie(*m_die->m_cu, nextCur);
    }
    return *this;
}

Die::ChildrenRange::Iterator Die::ChildrenRange::Iterator::operator++(int)
{
    auto tmp = *this;
    ++(*this);
    return tmp;
}

bool Die::ChildrenRange::Iterator::operator==(const Die::ChildrenRange::Iterator& rhs) const
{
    auto lhsNull = !m_die.has_value() || !m_die->abbrevEntry();
    auto rhsNull = !rhs.m_die.has_value() || !rhs.m_die->abbrevEntry();
    if(lhsNull && rhsNull) {
        return true;
    }
    if(lhsNull || rhsNull) {
        return false;
    }
    return m_die->abbrevEntry() == rhs->abbrevEntry() && m_die->next() == rhs->next();
}

Dwarf::Dwarf(const Elf& parent)
    : m_elf(&parent)
{
    m_compileUnits = parseCompileUnits(*this, parent);
}

const std::unordered_map<std::uint64_t, Abbrev>& Dwarf::getAbbrevTable(size_t offset)
{
    auto it = m_abbrevTables.find(offset);
    if(it == m_abbrevTables.end()) {
        it = m_abbrevTables.emplace(offset, parseAbbrevTable(*m_elf, offset)).first;
    }
    return it->second;
}

const CompileUnit* Dwarf::compileUnitContainingAddress(FileAddr address) const
{
    for(auto& cu : m_compileUnits) {
        if(cu->root().containsAddress(address)) {
            return cu.get();
        }
    }
    return nullptr;
}

std::optional<Die> Dwarf::functionContainingAddress(FileAddr address) const
{
    index();
    for(auto& [name, entry] : m_functionIndex) {
        Cursor cur({entry.pos, entry.cu->data().end()});
        auto d = parseDie(*entry.cu, cur);
        if(d.containsAddress(address) && d.abbrevEntry()->tag == DW_TAG_subprogram) {
            return d;
        }
    }
    return std::nullopt;
}

std::vector<Die> Dwarf::findFunctions(std::string name) const
{
    index();
    std::vector<Die> found;
    auto [begin, end] = m_functionIndex.equal_range(name);
    std::transform(begin, end, std::back_inserter(found), [](auto& pair) {
        auto [name, entry] = pair;
        Cursor cur({entry.pos, entry.cu->data().end()});
        return parseDie(*entry.cu, cur);
    });
    return found;
}

LineTable::Iterator Dwarf::lineEntryAtAddress(FileAddr address) const
{
    auto cu = compileUnitContainingAddress(address);
    if(!cu) {
        return {};
    }
    return cu->lines().getEntryByAddress(address);
}

std::vector<Die> Dwarf::inlineStackAtAddress(FileAddr address) const
{
    auto func = functionContainingAddress(address);
    std::vector<Die> stack;
    if(func) {
        stack.push_back(*func);
        while(true) {
            const auto& children = stack.back().children();
            auto found           = std::find_if(children.begin(), children.end(), [=](auto& child) {
                return child.abbrevEntry()->tag == DW_TAG_inlined_subroutine
                    && child.containsAddress(address);
            });
            if(found == children.end()) {
                break;
            } else {
                stack.push_back(*found);
            }
        }
    }
    return stack;
}

void Dwarf::index() const
{
    if(!m_functionIndex.empty()) {
        return;
    }
    for(auto& cu : m_compileUnits) {
        indexDie(cu->root());
    }
}

void Dwarf::indexDie(const Die& current) const
{
    bool hasRange   = current.contains(DW_AT_low_pc) || current.contains(DW_AT_ranges);
    bool isFunction = current.abbrevEntry()->tag == DW_TAG_subprogram
                   || current.abbrevEntry()->tag == DW_TAG_inlined_subroutine;
    if(hasRange && isFunction) {
        if(auto name = current.name(); name) {
            IndexEntry entry{current.cu(), current.position()};
            m_functionIndex.emplace(*name, entry);
        }
    }
    for(auto child : current.children()) {
        indexDie(child);
    }
}

} // namespace pdb

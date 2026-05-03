#include <libpdb/bit.hpp>
#include <libpdb/dwarf.hpp>
#include <libpdb/elf.hpp>
#include <libpdb/error.hpp>
#include <libpdb/process.hpp>
#include <libpdb/types.hpp>

#include <algorithm>
#include <string_view>
#include <variant>

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

uint64_t parseEhFramePointerWithBase(Cursor& cur, uint8_t encoding, uint64_t base)
{
    switch(encoding & 0x0F) {
        case DW_EH_PE_absptr:
            return base + cur.u64();
        case DW_EH_PE_uleb128:
            return base + cur.uleb128();
        case DW_EH_PE_udata2:
            return base + cur.u16();
        case DW_EH_PE_udata4:
            return base + cur.u32();
        case DW_EH_PE_udata8:
            return base + cur.u64();
        case DW_EH_PE_sleb128:
            return base + cur.sleb128();
        case DW_EH_PE_sdata2:
            return base + cur.s16();
        case DW_EH_PE_sdata4:
            return base + cur.s32();
        case DW_EH_PE_sdata8:
            return base + cur.s64();
        default:
            Error::send("Unknown eh_frame pointer encoding");
    }
}

uint64_t parseEhFramePointer(const Elf& elf, Cursor& cur, uint8_t encoding, uint64_t pc,
                             uint64_t textSectionStart, uint64_t dataSectionStart,
                             uint64_t funcStart)
{
    uint64_t base = 0;
    switch(encoding & 0x70) {
        case DW_EH_PE_absptr:
            break;
        case DW_EH_PE_pcrel:
            base = pc;
            break;
        case DW_EH_PE_textrel:
            base = textSectionStart;
            break;
        case DW_EH_PE_datarel:
            base = dataSectionStart;
            break;
        case DW_EH_PE_funcrel:
            base = funcStart;
            break;
        default:
            Error::send("Unknown eh_frame pointer encoding");
    }
    return parseEhFramePointerWithBase(cur, encoding, base);
}

CallFrameInformation::CommonInformationEntry parseCie(Cursor cur)
{
    auto start   = cur.position();
    auto length  = cur.u32() + 4;
    auto id      = cur.u32();
    auto version = cur.u8();

    if(!(version == 1 || version == 3 || version == 4)) {
        Error::send("Invalid CIE version");
    }

    auto augmentation = cur.string();

    if(!augmentation.empty() && augmentation[0] != 'z') {
        Error::send("Invalid CIE augmentation");
    }

    if(version == 4) {
        auto addressSize = cur.u8();
        auto segmentSize = cur.u8();
        if(addressSize != 8) {
            Error::send("Invalid address size");
        }
        if(segmentSize != 0) {
            Error::send("Invalid segment size");
        }
    }

    auto codeAlignmentFactor   = cur.uleb128();
    auto dataAlignmentFactor   = cur.sleb128();
    auto returnAddressRegister = version == 1 ? cur.u8() : cur.uleb128();

    uint8_t fdePointerEncoding = DW_EH_PE_udata8 | DW_EH_PE_absptr;
    for(auto c : augmentation) {
        switch(c) {
            case 'z':
                cur.uleb128();
                break;
            case 'R':
                fdePointerEncoding = cur.u8();
                break;
            case 'L':
                cur.u8();
                break;
            case 'P':
            {
                auto encoding = cur.u8();
                (void)parseEhFramePointerWithBase(cur, encoding, 0);
                break;
            }
            default:
                Error::send("Invalid CIE augmentation");
        }
    }

    Span<const std::byte> instructions = {cur.position(), start + length};
    bool fdeHasAugmentation            = !augmentation.empty();
    return {length,
            codeAlignmentFactor,
            dataAlignmentFactor,
            fdeHasAugmentation,
            fdePointerEncoding,
            instructions};
}

CallFrameInformation::FrameDescriptionEntry parseFde(const CallFrameInformation& cfi, Cursor cur)
{
    auto start  = cur.position();
    auto length = cur.u32() + 4;

    auto elf           = cfi.dwarfInfo().elfFile();
    auto currentOffset = elf->dataPointerAsFileOffset(cur.position());
    FileOffset cieOffset{*elf, currentOffset.offset() - cur.u32()};
    auto& cie = cfi.getCie(cieOffset);

    currentOffset            = elf->dataPointerAsFileOffset(cur.position());
    auto textSectionStart    = elf->getSectionStartAddress(".text").value_or(FileAddr{});
    auto initialLocationAddr = parseEhFramePointer(
        *elf, cur, cie.fdePointerEncoding, currentOffset.offset(), textSectionStart.addr(), 0, 0);
    FileAddr initialLocation{*elf, initialLocationAddr};

    auto addressRange = parseEhFramePointerWithBase(cur, cie.fdePointerEncoding, 0);

    if(cie.fdeHasAugmentation) {
        auto augmentationLength = cur.uleb128();
        cur += augmentationLength;
    }

    Span<const std::byte> instructions = {cur.position(), start + length};
    return {length, &cie, initialLocation, addressRange, instructions};
}

CallFrameInformation::EhHdr parseEhHdr(Dwarf& dwarf)
{
    auto elf              = dwarf.elfFile();
    auto ehHdrStart       = *elf->getSectionStartAddress(".eh_frame_hdr");
    auto textSectionStart = *elf->getSectionStartAddress(".text");

    auto ehHdrData = elf->getSectionContents(".eh_frame_hdr");
    Cursor cur(ehHdrData);

    auto start         = cur.position();
    auto version       = cur.u8();
    auto ehFramePtrEnc = cur.u8();
    auto fdeCountEnc   = cur.u8();
    auto tableEnc      = cur.u8();
    (void)parseEhFramePointerWithBase(cur, ehFramePtrEnc, 0);

    auto fdeCount = parseEhFramePointerWithBase(cur, fdeCountEnc, 0);

    auto searchTable = cur.position();
    return {start, searchTable, fdeCount, tableEnc, nullptr};
}

size_t ehFramePointerEncodingSize(uint8_t encoding)
{
    switch(encoding & 0x7) {
        case DW_EH_PE_absptr:
            return 8;
        case DW_EH_PE_udata2:
            return 2;
        case DW_EH_PE_udata4:
            return 4;
        case DW_EH_PE_udata8:
            return 8;
        default:
            Error::send("Invalid pointer encoding");
    }
}

std::unique_ptr<CallFrameInformation> parseCallFrameInformation(Dwarf& dwarf)
{
    auto ehHdr = parseEhHdr(dwarf);
    return std::make_unique<CallFrameInformation>(&dwarf, ehHdr);
}

struct UndefinedRule
{ };
struct SameRule
{ };
struct OffsetRule
{
    int64_t offset;
};
struct ValOffsetRule
{
    int64_t offset;
};
struct RegisterRule
{
    uint32_t reg;
};
struct CfaRegisterRule
{
    uint32_t reg;
    int64_t offset;
};

struct UnwindContext
{
    Cursor cur{{nullptr, nullptr}};
    FileAddr location;
    CfaRegisterRule cfaRule;

    using Rule    = std::variant<UndefinedRule, SameRule, OffsetRule, ValOffsetRule, RegisterRule>;
    using Ruleset = std::unordered_map<uint32_t, Rule>;
    Ruleset cieRegisterRules;
    Ruleset registerRules;
    std::vector<std::pair<Ruleset, CfaRegisterRule>> ruleStack;
};

void executeCfiInstruction(const Elf& elf, const CallFrameInformation::FrameDescriptionEntry& fde,
                           UnwindContext& ctx, FileAddr pc)
{
    auto& cie = *fde.cie;
    auto& cur  = ctx.cur;

    auto textSectionStart = *elf.getSectionStartAddress(".text");
    auto pltStart         = elf.getSectionStartAddress(".got.plt").value_or(FileAddr{});

    auto opcode         = cur.u8();
    auto primaryOpcode  = opcode & 0xC0;
    auto extendedOpcode = opcode & 0x3F;
    if(primaryOpcode) {
        switch(primaryOpcode) {
            case DW_CFA_advance_loc:
                ctx.location += extendedOpcode * cie.codeAlignmentFactor;
                break;
            case DW_CFA_offset:
            {
                auto offset = static_cast<int64_t>(cur.uleb128()) * cie.dataAlignmentFactor;
                ctx.registerRules.emplace(extendedOpcode, OffsetRule{offset});
                break;
            }
            case DW_CFA_restore:
                ctx.registerRules.emplace(extendedOpcode, ctx.cieRegisterRules.at(extendedOpcode));
                break;
        }
    } else if(extendedOpcode) {
        switch(extendedOpcode) {
            case DW_CFA_set_loc:
            {
                auto currentOffset = elf.dataPointerAsFileOffset(cur.position());
                auto loc           = parseEhFramePointer(elf, cur, cie.fdePointerEncoding,
                                                         currentOffset.offset(), textSectionStart.addr(),
                                                         pltStart.addr(), fde.initialLocation.addr());
                ctx.location       = FileAddr{elf, loc};
                break;
            }
            case DW_CFA_advance_loc1:
                ctx.location += cur.u8() * cie.codeAlignmentFactor;
                break;
            case DW_CFA_advance_loc2:
                ctx.location += cur.u16() * cie.codeAlignmentFactor;
                break;
            case DW_CFA_advance_loc4:
                ctx.location += cur.u32() * cie.codeAlignmentFactor;
                break;
            case DW_CFA_def_cfa:
                ctx.cfaRule.reg    = cur.uleb128();
                ctx.cfaRule.offset = cur.uleb128();
                break;
            case DW_CFA_def_cfa_sf:
                ctx.cfaRule.reg    = cur.uleb128();
                ctx.cfaRule.offset = cur.sleb128() * cie.dataAlignmentFactor;
                break;
            case DW_CFA_def_cfa_register:
                ctx.cfaRule.reg = cur.uleb128();
                break;
            case DW_CFA_def_cfa_offset:
                ctx.cfaRule.offset = cur.uleb128();
                break;
            case DW_CFA_def_cfa_offset_sf:
                ctx.cfaRule.offset = cur.sleb128() * cie.dataAlignmentFactor;
                break;
            case DW_CFA_def_cfa_expression:
                Error::send("DWARF expression not yet implemented");
            case DW_CFA_undefined:
                ctx.registerRules.emplace(cur.uleb128(), UndefinedRule{});
                break;
            case DW_CFA_same_value:
                ctx.registerRules.emplace(cur.uleb128(), SameRule{});
                break;
            case DW_CFA_offset_extended:
            {
                auto reg    = cur.uleb128();
                auto offset = static_cast<int64_t>(cur.uleb128()) * cie.dataAlignmentFactor;
                ctx.registerRules.emplace(reg, OffsetRule{offset});
                break;
            }
            case DW_CFA_offset_extended_sf:
            {
                auto reg    = cur.uleb128();
                auto offset = cur.sleb128() * cie.dataAlignmentFactor;
                ctx.registerRules.emplace(reg, OffsetRule{offset});
                break;
            }
            case DW_CFA_val_offset:
            {
                auto reg    = cur.uleb128();
                auto offset = static_cast<int64_t>(cur.uleb128()) * cie.dataAlignmentFactor;
                ctx.registerRules.emplace(reg, ValOffsetRule{offset});
                break;
            }
            case DW_CFA_val_offset_sf:
            {
                auto reg    = cur.uleb128();
                auto offset = cur.sleb128() * cie.dataAlignmentFactor;
                ctx.registerRules.emplace(reg, ValOffsetRule{offset});
            }
            case DW_CFA_register:
            {
                auto reg = cur.uleb128();
                ctx.registerRules.emplace(reg, RegisterRule{static_cast<uint32_t>(cur.uleb128())});
                break;
            }
            case DW_CFA_expression:
                Error::send("DWARF expressions not yet implemented");
            case DW_CFA_val_expression:
                Error::send("DWARF expressions not yet implemented");
            case DW_CFA_restore_extended:
            {
                auto reg = cur.uleb128();
                ctx.registerRules.emplace(reg, ctx.cieRegisterRules.at(reg));
                break;
            }
            case DW_CFA_remember_state:
            {
                ctx.ruleStack.push_back({ctx.registerRules, ctx.cfaRule});
                break;
            }
            case DW_CFA_restore_state:
                ctx.registerRules = ctx.ruleStack.back().first;
                ctx.cfaRule       = ctx.ruleStack.back().second;
                ctx.ruleStack.pop_back();
                break;
        }
    }
}

Registers executeUnwindRules(UnwindContext& ctx, Registers& oldRegs, const Process& proc)
{
    auto unwoundRegs = oldRegs;
    auto cfaRegInfo  = registerInfoByDwarf(ctx.cfaRule.reg);
    auto cfa         = std::get<uint64_t>(oldRegs.read(cfaRegInfo)) + ctx.cfaRule.offset;
    oldRegs.setCfa(VirtAddr{cfa});
    unwoundRegs.writeById(RegisterId::rsp, {cfa}, false);

    for(auto [reg, rule] : ctx.registerRules) {
        auto regInfo = registerInfoByDwarf(reg);

        if(auto undef = std::get_if<UndefinedRule>(&rule)) {
            unwoundRegs.undefine(regInfo.id);
        } else if(auto same = std::get_if<SameRule>(&rule)) {
            // Do nothing
        } else if(auto reg = std::get_if<RegisterRule>(&rule)) {
            auto otherReg = registerInfoByDwarf(reg->reg);
            unwoundRegs.write(regInfo, oldRegs.read(otherReg), false);
        } else if(auto offset = std::get_if<OffsetRule>(&rule)) {
            auto addr  = VirtAddr{cfa + offset->offset};
            auto value = fromBytes<uint64_t>(proc.readMemory(addr, 8).data());
            unwoundRegs.write(regInfo, {value}, false);
        } else if(auto valOffset = std::get_if<ValOffsetRule>(&rule)) {
            auto addr = cfa + valOffset->offset;
            unwoundRegs.write(regInfo, {addr}, false);
        }
    }
    return unwoundRegs;
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

const std::byte* CallFrameInformation::EhHdr::operator[](FileAddr address) const
{
    auto elf              = address.elfFile();
    auto textSectionStart = *elf->getSectionStartAddress(".text");
    auto encodingSize     = ehFramePointerEncodingSize(encoding);
    auto rowSize          = encodingSize * 2;

    size_t low  = 0;
    size_t high = count - 1;
    while(low <= high) {
        size_t mid = (low + high) / 2;
        Cursor cur({searchTable + mid * rowSize, searchTable + count * rowSize});
        auto currentOffset = elf->dataPointerAsFileOffset(cur.position());
        auto ehHdrOffset   = elf->dataPointerAsFileOffset(start);
        auto entryAddress  = parseEhFramePointer(*elf, cur, encoding, currentOffset.offset(),
                                                 textSectionStart.addr(), ehHdrOffset.offset(), 0);
        if(entryAddress < address.addr()) {
            low = mid + 1;
        } else if(entryAddress > address.addr()) {
            if(mid == 0) {
                Error::send("Address not found in eh_hdr");
            }
            high = mid - 1;
        } else {
            high = mid;
            break;
        }
    }

    Cursor cur({searchTable + high * rowSize + encodingSize, searchTable + count * rowSize});
    auto currentOffset = elf->dataPointerAsFileOffset(cur.position());
    auto ehHdrOffset   = elf->dataPointerAsFileOffset(start);
    auto fdeOffsetInt  = parseEhFramePointer(*elf, cur, encoding, currentOffset.offset(),
                                             textSectionStart.addr(), ehHdrOffset.offset(), 0);
    FileOffset fdeOffset{*elf, fdeOffsetInt};
    return elf->fileOffsetAsDataPointer(fdeOffset);
}

const CallFrameInformation::CommonInformationEntry&
CallFrameInformation::getCie(FileOffset at) const
{
    auto offset = at.offset();
    if(m_cieMap.count(offset)) {
        return m_cieMap.at(offset);
    }

    auto section = at.elfFile()->getSectionContents(".eh_frame");
    Cursor cur({at.elfFile()->fileOffsetAsDataPointer(at), section.end()});
    auto cie = parseCie(cur);
    m_cieMap.emplace(offset, cie);
    return m_cieMap.at(offset);
}

Registers CallFrameInformation::unwind(const Process& proc, FileAddr pc, Registers& regs) const
{
    auto fdeStart   = m_ehHdr[pc];
    auto ehFrameEnd = m_dwarf->elfFile()->getSectionContents(".eh_frame").end();

    Cursor cur({fdeStart, ehFrameEnd});
    auto fde = parseFde(*this, cur);
    if(pc < fde.initialLocation || pc >= fde.initialLocation + fde.addressRange) {
        Error::send("No unwind information at pc");
    }

    UnwindContext ctx{};
    ctx.cur = Cursor(fde.cie->instructions);

    while(!ctx.cur.finished()) {
        executeCfiInstruction(*m_dwarf->elfFile(), fde, ctx, pc);
    }

    ctx.cieRegisterRules = ctx.registerRules;
    ctx.cur              = Cursor(fde.instruction);
    ctx.location         = fde.initialLocation;

    while(!ctx.cur.finished() && ctx.location <= pc) {
        executeCfiInstruction(*m_dwarf->elfFile(), fde, ctx, pc);
    }

    return executeUnwindRules(ctx, regs, proc);
}

Dwarf::Dwarf(const Elf& parent)
    : m_elf(&parent)
{
    m_compileUnits = parseCompileUnits(*this, parent);
    m_cfi          = parseCallFrameInformation(*this);
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

#include <libpdb/bit.hpp>
#include <libpdb/disassembler.hpp>
#include <libpdb/target.hpp>
#include <libpdb/types.hpp>

#include <cxxabi.h>

#include <csignal>
#include <fstream>
#include <optional>

namespace pdb {

namespace {

std::unique_ptr<Elf> createLoadedElf(const Process& proc, const std::filesystem::path& path)
{
    auto auxv = proc.getAuxv();
    auto obj  = std::make_unique<Elf>(path);
    obj->notifyLoaded(VirtAddr{auxv[AT_ENTRY] - obj->header().e_entry});
    return obj;
}

std::filesystem::path dumpVdso(const Process& proc, VirtAddr address)
{
    char tmpDir[] = "/tmp/pdb-XXXXXX";
    mkdtemp(tmpDir);
    auto vdsoDumpPath = std::filesystem::path(tmpDir) / "linux-vdso.so.1";
    std::ofstream vdsoDump(vdsoDumpPath, std::ios::binary);
    auto vdsoHeader = proc.readMemoryAs<Elf64_Ehdr>(address);
    auto vdsoSize   = vdsoHeader.e_shoff + vdsoHeader.e_shentsize * vdsoHeader.e_shnum;
    auto vdsoBytes  = proc.readMemory(address, vdsoSize);
    vdsoDump.write(reinterpret_cast<const char*>(vdsoBytes.data()), vdsoBytes.size());
    return vdsoDumpPath;
}

void memcpyBits(uint8_t* dest, uint32_t destBit, const uint8_t* src, uint32_t srcBit,
                uint32_t nBits)
{
    for(; nBits; --nBits, ++srcBit, ++destBit) {
        uint8_t destMask = 1 << (destBit % 8);
        dest[destBit / 8] &= ~destMask;
        auto srcMask                = 1 << (srcBit % 8);
        auto correspondingSrcBitSet = src[srcBit / 8] & srcMask;
        if(correspondingSrcBitSet) {
            dest[destBit / 8] |= destMask;
        }
    }
}

} // namespace

std::unique_ptr<Target> Target::launch(std::filesystem::path path,
                                       std::optional<int> stdoutReplacement)
{
    auto proc   = Process::launch(path, true, stdoutReplacement);
    auto obj    = createLoadedElf(*proc, path);
    auto target = std::unique_ptr<Target>(new Target(std::move(proc), std::move(obj)));
    target->getProcess().setTarget(target.get());

    auto entryPoint = VirtAddr{target->getProcess().getAuxv()[AT_ENTRY]};
    auto& entryBp   = target->createAddressBreakpoint(entryPoint, false, true);
    entryBp.installHitHandler([t = target.get()] {
        t->resolveDynamicLinkerRendezvous();
        return true;
    });
    entryBp.enable();
    return target;
}

std::unique_ptr<Target> Target::attach(pid_t pid)
{
    auto elfPath = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto proc    = Process::attach(pid);
    auto obj     = createLoadedElf(*proc, elfPath);
    auto target  = std::unique_ptr<Target>(new Target(std::move(proc), std::move(obj)));
    target->getProcess().setTarget(target.get());
    target->resolveDynamicLinkerRendezvous();
    return target;
}

void Target::notifyStop(const StopReason& reason)
{
    m_threads.at(reason.tid).frames.unwind();
}

FileAddr Target::getPcFileAddress(std::optional<pid_t> otid) const
{
    return m_process->getProgramCounter(otid).toFileAddr(m_elves);
}

StopReason Target::stepIn(std::optional<pid_t> otid)
{
    auto tid     = otid.value_or(m_process->currentThread());
    auto& stack  = getStack(tid);
    auto& thread = m_threads.at(tid);
    if(stack.inlineHeight() > 0) {
        stack.simulateInlinedStepIn();
        StopReason reason(tid, ProcessState::Stopped, SIGTRAP, TrapType::SingleStep);
        thread.state->reason = reason;
        return reason;
    }

    auto origLine = lineEntryAtPc(tid);
    do {
        auto reason = m_process->stepInstruction(tid);
        if(!reason.isStep()) {
            thread.state->reason = reason;
            return reason;
        }
    } while((lineEntryAtPc(tid) == origLine || lineEntryAtPc(tid)->endSequence)
            && lineEntryAtPc(tid) != LineTable::Iterator{});

    auto pc = getPcFileAddress(tid);
    if(pc.elfFile() != nullptr) {
        auto& dwarf = pc.elfFile()->getDwarf();
        auto func   = dwarf.functionContainingAddress(pc);
        if(func && func->lowPc() == pc) {
            auto line = lineEntryAtPc(tid);
            if(line != LineTable::Iterator{}) {
                ++line;
                return runUntilAddress(line->address.toVirtAddr(), tid);
            }
        }
    }

    StopReason reason(tid, ProcessState::Stopped, SIGTRAP, TrapType::SingleStep);
    thread.state->reason = reason;
    return reason;
}

StopReason Target::stepOver(std::optional<pid_t> otid)
{
    auto tid      = otid.value_or(m_process->currentThread());
    auto& thread  = m_threads.at(tid);
    auto& stack   = getStack(tid);
    auto origLine = lineEntryAtPc(tid);

    Disassembler disas(*m_process);
    StopReason reason;
    do {
        auto inlineStack          = stack.inlineStackAtPc();
        auto atStartOfInlineFrame = stack.inlineHeight() > 0;
        if(atStartOfInlineFrame) {
            auto frameToSkip   = inlineStack[inlineStack.size() - stack.inlineHeight()];
            auto returnAddress = frameToSkip.highPc().toVirtAddr();
            reason             = runUntilAddress(returnAddress, tid);
            if(!reason.isStep() || m_process->getProgramCounter(tid) != returnAddress) {
                thread.state->reason = reason;
                return reason;
            }
        } else if(auto instructions = disas.disassemble(2, m_process->getProgramCounter(tid));
                  instructions[0].text.rfind("call") == 0) {
            reason = runUntilAddress(instructions[1].address, tid);
            if(!reason.isStep() || m_process->getProgramCounter(tid) != instructions[1].address) {
                thread.state->reason = reason;
                return reason;
            }
        } else {
            reason = m_process->stepInstruction(tid);
            if(!reason.isStep()) {
                thread.state->reason = reason;
                return reason;
            }
        }
    } while((lineEntryAtPc(tid) == origLine || lineEntryAtPc(tid)->endSequence)
            && lineEntryAtPc(tid) != LineTable::Iterator{});
    thread.state->reason = reason;
    return reason;
}

StopReason Target::stepOut(std::optional<pid_t> otid)
{
    auto tid             = otid.value_or(m_process->currentThread());
    auto& stack          = getStack(tid);
    auto inlineStack     = stack.inlineStackAtPc();
    auto hasInlineFrames = inlineStack.size() > 1;
    auto atInlineFrame   = stack.inlineHeight() < inlineStack.size() - 1;

    if(hasInlineFrames && atInlineFrame) {
        auto currentFrame  = inlineStack[inlineStack.size() - stack.inlineHeight() - 1];
        auto returnAddress = currentFrame.highPc().toVirtAddr();
        return runUntilAddress(returnAddress, tid);
    }

    auto& regs = stack.frames()[stack.currentFrameIndex() + 1].regs;
    VirtAddr returnAddress{regs.readByIdAs<uint64_t>(RegisterId::rip)};

    StopReason reason;
    for(auto frames = stack.frames().size(); stack.frames().size() >= frames;) {
        reason = runUntilAddress(returnAddress, tid);
        if(!reason.isBreakpoint() || m_process->getProgramCounter() != returnAddress) {
            return reason;
        }
    }

    return reason;
}

LineTable::Iterator Target::lineEntryAtPc(std::optional<pid_t> otid) const
{
    auto pc = getPcFileAddress(otid);
    if(!pc.elfFile()) {
        return LineTable::Iterator();
    }
    auto cu = pc.elfFile()->getDwarf().compileUnitContainingAddress(pc);
    if(!cu) {
        return LineTable::Iterator();
    }
    return cu->lines().getEntryByAddress(pc);
}

StopReason Target::runUntilAddress(VirtAddr address, std::optional<pid_t> otid)
{
    auto tid    = otid.value_or(m_process->currentThread());
    auto& stack = getStack(tid);

    BreakpointSite* breakpointToRemove = nullptr;
    if(!m_process->breakpointSites().containsAddress(address)) {
        breakpointToRemove = &m_process->createBreakpointSite(address, false, true);
        breakpointToRemove->enable();
    }

    m_process->resume(tid);
    auto reason = m_process->waitOnSignal(tid);
    if(reason.isBreakpoint() && m_process->getProgramCounter(tid) == address) {
        reason.trapReason = TrapType::SingleStep;
    }

    if(breakpointToRemove) {
        m_process->breakpointSites().removeByAddress(breakpointToRemove->address());
    }
    m_threads.at(tid).state->reason = reason;
    return reason;
}

Target::FindFunctionResult Target::findFunctions(std::string name) const
{
    FindFunctionResult result;

    m_elves.forEach([&](Elf& elf) {
        auto dwarfFound = elf.getDwarf().findFunctions(name);
        if(dwarfFound.empty()) {
            auto elfFound = elf.getSymbolsByName(name);
            for(auto sym : elfFound) {
                result.elfFunctions.push_back(std::pair{&elf, sym});
            }
        } else {
            result.dwarfFunctions.insert(result.dwarfFunctions.end(), dwarfFound.begin(),
                                         dwarfFound.end());
        }
    });
    return result;
}

Breakpoint& Target::createAddressBreakpoint(VirtAddr address, bool hardware, bool internal)
{
    return m_breakpoints.push(std::unique_ptr<AddressBreakpoint>(
        new AddressBreakpoint(*this, address, hardware, internal)));
}

Breakpoint& Target::createFunctionBreakpoint(std::string functionName, bool hardware, bool internal)
{
    return m_breakpoints.push(std::unique_ptr<FunctionBreakpoint>(
        new FunctionBreakpoint(*this, functionName, hardware, internal)));
}

Breakpoint& Target::createLineBreakpoint(std::filesystem::path file, size_t line, bool hardware,
                                         bool internal)
{
    return m_breakpoints.push(
        std::unique_ptr<LineBreakpoint>(new LineBreakpoint(*this, file, line, hardware, internal)));
}

std::string Target::functionNameAtAddress(VirtAddr address) const
{
    auto fileAddress     = address.toFileAddr(m_elves);
    auto obj             = fileAddress.elfFile();
    auto func            = obj->getDwarf().functionContainingAddress(fileAddress);
    auto elfFilename     = obj->path().filename().string();
    std::string funcName = "";

    if(func && func->name()) {
        funcName = *func->name();
    } else if(auto elfFunc = obj->getSymbolContainingAddress(fileAddress);
              elfFunc && ELF64_ST_TYPE(elfFunc.value()->st_info) == STT_FUNC) {
        funcName = obj->getString(elfFunc.value()->st_name);
    }

    if(!funcName.empty()) {
        return elfFilename + "`" + funcName;
    }

    return "";
}

std::optional<r_debug> Target::readDynamicLinkerRendezvous() const
{
    if(m_dynamicLinkerRendezvousAddress.addr()) {
        return m_process->readMemoryAs<r_debug>(m_dynamicLinkerRendezvousAddress);
    }
    return std::nullopt;
}

std::vector<LineTable::Iterator> Target::getLineEntriesByLine(std::filesystem::path path,
                                                              std::size_t line) const
{
    std::vector<LineTable::Iterator> entries;
    m_elves.forEach([&](Elf& elf) {
        for(auto& cu : elf.getDwarf().compileUnits()) {
            auto newEntries = cu->lines().getEntriesByLine(path, line);
            entries.insert(entries.end(), newEntries.begin(), newEntries.end());
        }
    });
    return entries;
}

void Target::notifyThreadLifecycleEvent(const StopReason& reason)
{
    auto tid = reason.tid;
    if(reason.reason == ProcessState::Stopped) {
        auto& state = m_process->threadStates()[tid];
        m_threads.emplace(tid, Thread{&state, Stack{this, tid}});
    } else {
        m_threads.erase(tid);
    }
}

std::vector<std::byte> Target::readLocationData(const DwarfExpression::Result& loc, size_t size,
                                                std::optional<pid_t> otid) const
{
    auto tid = otid.value_or(m_process->currentThread());

    if(auto simpleLoc = std::get_if<DwarfExpression::SimpleLocation>(&loc)) {
        if(auto regLoc = std::get_if<DwarfExpression::RegisterResult>(simpleLoc)) {
            auto regInfo  = registerInfoByDwarf(regLoc->regNum);
            auto regValue = m_threads.at(tid).frames.currentFrame().regs.read(regInfo);
            auto getBytes = [](auto value) {
                std::vector<std::byte> bytes(sizeof(value));
                auto begin = reinterpret_cast<const std::byte*>(&value);
                std::copy(begin, begin + sizeof(value), bytes.data());
                return bytes;
            };
            return std::visit(getBytes, regValue);
        } else if(auto addrRes = std::get_if<DwarfExpression::AddressResult>(simpleLoc)) {
            return m_process->readMemory(addrRes->address, size);
        } else if(auto dataRes = std::get_if<DwarfExpression::DataResult>(simpleLoc)) {
            return {dataRes->data.begin(), dataRes->data.end()};
        } else if(auto literalRes = std::get_if<DwarfExpression::LiteralResult>(simpleLoc)) {
            auto begin = reinterpret_cast<const std::byte*>(&literalRes->value);
            return {begin, begin + size};
        }
    } else if(auto piecesRes = std::get_if<DwarfExpression::PiecesResult>(&loc)) {
        std::vector<std::byte> data(size);
        size_t offset = 0;
        for(auto& piece : piecesRes->pieces) {
            auto byteSize  = (piece.bitSize + 7) / 8;
            auto pieceData = readLocationData(piece.location, byteSize, otid);
            if(offset % 8 == 0 && piece.offset == 0 && piece.bitSize % 8 == 0) {
                std::copy(pieceData.begin(), pieceData.end(), data.begin() + offset / 8);
                offset += piece.bitSize;
            } else {
                auto dest = reinterpret_cast<uint8_t*>(data.data());
                auto src  = reinterpret_cast<uint8_t*>(pieceData.data());
                memcpyBits(dest, 0, src, piece.offset, piece.bitSize);
            }
        }
        return data;
    }
    Error::send("Invalid location type");
}

void Target::resolveDynamicLinkerRendezvous()
{
    if(m_dynamicLinkerRendezvousAddress.addr()) {
        return;
    }

    auto dynamicSection = m_mainElf->getSection(".dynamic");
    auto dynamicStart   = FileAddr{*m_mainElf, dynamicSection.value()->sh_addr};
    auto dynamicSize    = dynamicSection.value()->sh_size;
    auto dynamicBytes   = m_process->readMemory(dynamicStart.toVirtAddr(), dynamicSize);

    std::vector<Elf64_Dyn> dynamicEntries(dynamicSize / sizeof(Elf64_Dyn));
    std::copy(dynamicBytes.begin(), dynamicBytes.end(),
              reinterpret_cast<std::byte*>(dynamicEntries.data()));

    for(auto entry : dynamicEntries) {
        if(entry.d_tag == DT_DEBUG) {
            m_dynamicLinkerRendezvousAddress = VirtAddr{entry.d_un.d_ptr};
            reloadDynamicLibraries();

            auto debugInfo      = readDynamicLinkerRendezvous();
            auto debugStateAddr = VirtAddr{debugInfo->r_brk};
            auto& debugStateBp  = createAddressBreakpoint(debugStateAddr, false, true);
            debugStateBp.installHitHandler([&] {
                reloadDynamicLibraries();
                return true;
            });
            debugStateBp.enable();
        }
    }
}

void Target::reloadDynamicLibraries()
{
    auto debug = readDynamicLinkerRendezvous();
    if(!debug) {
        return;
    }

    auto entryPtr = debug->r_map;
    while(entryPtr != nullptr) {
        auto entryAddr = VirtAddr{reinterpret_cast<uint64_t>(entryPtr)};
        auto entry     = m_process->readMemoryAs<link_map>(entryAddr);
        entryPtr       = entry.l_next;

        auto nameAddr  = VirtAddr{reinterpret_cast<uint64_t>(entry.l_name)};
        auto nameBytes = m_process->readMemory(nameAddr, 4096);
        auto name      = std::filesystem::path{reinterpret_cast<char*>(nameBytes.data())};
        if(name.empty()) {
            continue;
        }

        const Elf* found    = nullptr;
        const auto vdsoName = "linux-vdso.so.1";
        if(name == vdsoName) {
            found = m_elves.getElfByFilename(name.c_str());
        } else {
            found = m_elves.getElfByPath(name);
        }

        if(!found) {
            if(name == vdsoName) {
                name = dumpVdso(*m_process, VirtAddr{entry.l_addr});
            }
            auto newElf = std::make_unique<Elf>(name);
            newElf->notifyLoaded(VirtAddr{entry.l_addr});
            m_elves.push(std::move(newElf));
        }
    }

    m_breakpoints.forEach([&](auto& bp) { bp.resolve(); });
}

} // namespace pdb

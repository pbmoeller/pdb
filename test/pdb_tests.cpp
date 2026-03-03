#include <libpdb/bit.hpp>
#include <libpdb/elf.hpp>
#include <libpdb/error.hpp>
#include <libpdb/pipe.hpp>
#include <libpdb/process.hpp>
#include <libpdb/registers.hpp>
#include <libpdb/syscalls.hpp>

#include <catch2/catch_test_macros.hpp>

#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>

#include <fstream>
#include <regex>
#include <string>

namespace {

bool processExists(pid_t pid)
{
    auto ret = kill(pid, 0);
    return ret != -1 && errno != ESRCH;
}

char getProcessStatus(pid_t pid)
{
    std::ifstream statusFile("/proc/" + std::to_string(pid) + "/stat");
    std::string data;
    std::getline(statusFile, data);
    auto indexOfLastParenthesis = data.rfind(')');
    auto indexOfStatusIndicator = indexOfLastParenthesis + 2;
    return data[indexOfStatusIndicator];
}

int64_t getSectionLoadBias(std::filesystem::path path, Elf64_Addr fileAddress)
{
    auto command = std::string("readelf -WS ") + path.string();
    auto pipe    = popen(command.c_str(), "r");

    std::regex textRegex(R"(PROGBITS\s+(\w+)\s+(\w+)\s+(\w+))");
    char* line = nullptr;
    size_t len = 0;
    while(getline(&line, &len, pipe) != -1) {
        std::cmatch groups;
        if(std::regex_search(line, groups, textRegex)) {
            auto address = std::stol(groups[1], nullptr, 16);
            auto offset  = std::stol(groups[2], nullptr, 16);
            auto size    = std::stol(groups[3], nullptr, 16);
            if(address <= fileAddress && fileAddress < (address + size)) {
                free(line);
                pclose(pipe);
                return address - offset;
            }
        }
        free(line);
        line = nullptr;
    }
    pclose(pipe);
    pdb::Error::send("Could not find section load bias");
}

int64_t getEntryPointOffset(std::filesystem::path path)
{
    std::ifstream elfFile(path);
    Elf64_Ehdr header;
    elfFile.read(reinterpret_cast<char*>(&header), sizeof(header));
    auto entryFileAddress = header.e_entry;
    return entryFileAddress - getSectionLoadBias(path, entryFileAddress);
}

pdb::VirtAddr getLoadAddress(pid_t pid, int64_t offset)
{
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::regex mapRegex(R"((\w+)-\w+ ..(.). (\w+))");

    std::string data;
    while(std::getline(maps, data)) {
        std::smatch groups;
        std::regex_search(data, groups, mapRegex);

        if(groups[2] == 'x') {
            auto lowRange   = std::stol(groups[1], nullptr, 16);
            auto fileOffset = std::stol(groups[3], nullptr, 16);
            return pdb::VirtAddr(offset - fileOffset + lowRange);
        }
    }
    pdb::Error::send("Could not find load address");
}

} // namespace

TEST_CASE("Process::launch success", "[Process]")
{
    auto proc = pdb::Process::launch("yes");
    REQUIRE(processExists(proc->pid()));
}

TEST_CASE("Process::launch no such program", "[Process]")
{
    REQUIRE_THROWS_AS(pdb::Process::launch("program_that_does_not_exist"), pdb::Error);
}

TEST_CASE("Process::attach success", "[Process]")
{
    auto target = pdb::Process::launch("targets/run_endlessly", false);
    auto proc   = pdb::Process::attach(target->pid());
    REQUIRE(getProcessStatus(target->pid()) == 't');
}

TEST_CASE("Process::attach invalid PID", "[Process]")
{
    REQUIRE_THROWS_AS(pdb::Process::attach(0), pdb::Error);
}

TEST_CASE("Process::resume success", "[Process]")
{
    {
        auto proc = pdb::Process::launch("targets/run_endlessly");
        proc->resume();
        auto status  = getProcessStatus(proc->pid());
        auto success = status == 'R' || status == 'S';
        REQUIRE(success);
    }
    {
        auto target = pdb::Process::launch("targets/run_endlessly", false);
        auto proc   = pdb::Process::attach(target->pid());
        proc->resume();
        auto status  = getProcessStatus(proc->pid());
        auto success = status == 'R' || status == 'S';
        REQUIRE(success);
    }
}

TEST_CASE("Process::resume already terminated", "[Process]")
{
    auto proc = pdb::Process::launch("targets/end_immediately");
    proc->resume();
    proc->waitOnSignal();
    REQUIRE_THROWS_AS(proc->resume(), pdb::Error);
}

TEST_CASE("Write register works", "[register]")
{
    bool closeOnExec = false;
    pdb::Pipe channel(closeOnExec);

    auto proc = pdb::Process::launch("targets/reg_write", true, channel.getWrite());
    channel.closeWrite();

    proc->resume();
    proc->waitOnSignal();

    auto& regs = proc->getRegisters();
    regs.writeById(pdb::RegisterId::rsi, 0xcafecafe);

    proc->resume();
    proc->waitOnSignal();

    auto output = channel.read();
    REQUIRE(pdb::toStringView(output) == "0xcafecafe");

    regs.writeById(pdb::RegisterId::mm0, 0xba5eba11);

    proc->resume();
    proc->waitOnSignal();

    output = channel.read();
    REQUIRE(pdb::toStringView(output) == "0xba5eba11");

    regs.writeById(pdb::RegisterId::xmm0, 42.24);

    proc->resume();
    proc->waitOnSignal();

    output = channel.read();
    REQUIRE(pdb::toStringView(output) == "42.24");

    regs.writeById(pdb::RegisterId::st0, 42.24L);
    regs.writeById(pdb::RegisterId::fsw, uint16_t{0b0011100000000000});
    regs.writeById(pdb::RegisterId::ftw, uint16_t{0b0011111111111111});

    proc->resume();
    proc->waitOnSignal();

    output = channel.read();
    REQUIRE(pdb::toStringView(output) == "42.24");
}

TEST_CASE("Read register works", "[register]")
{
    auto proc  = pdb::Process::launch("targets/reg_read");
    auto& regs = proc->getRegisters();

    proc->resume();
    proc->waitOnSignal();

    REQUIRE(regs.readByIdAs<uint64_t>(pdb::RegisterId::r13) == 0xcafecafe);

    proc->resume();
    proc->waitOnSignal();

    REQUIRE(regs.readByIdAs<uint8_t>(pdb::RegisterId::r13b) == 42);

    proc->resume();
    proc->waitOnSignal();

    REQUIRE(regs.readByIdAs<pdb::byte64>(pdb::RegisterId::mm0) == pdb::toByte64(0xba5eba11));

    proc->resume();
    proc->waitOnSignal();

    auto b = pdb::toByte128(64.125);
    REQUIRE(regs.readByIdAs<pdb::byte128>(pdb::RegisterId::xmm0) == b);

    proc->resume();
    proc->waitOnSignal();

    REQUIRE(regs.readByIdAs<long double>(pdb::RegisterId::st0) == 64.125L);
}

TEST_CASE("Can create BreakpointSite", "[breakpoint]")
{
    auto proc  = pdb::Process::launch("targets/run_endlessly");
    auto& site = proc->createBreakpointSite(pdb::VirtAddr{42});
    REQUIRE(site.address().addr() == 42);
}

TEST_CASE("BreakpointSite ids increase", "[breakpoint]")
{
    auto proc = pdb::Process::launch("targets/run_endlessly");

    auto& s1 = proc->createBreakpointSite(pdb::VirtAddr{42});
    REQUIRE(s1.address().addr() == 42);

    auto& s2 = proc->createBreakpointSite(pdb::VirtAddr{43});
    REQUIRE(s2.id() == s1.id() + 1);

    auto& s3 = proc->createBreakpointSite(pdb::VirtAddr{44});
    REQUIRE(s3.id() == s1.id() + 2);

    auto& s4 = proc->createBreakpointSite(pdb::VirtAddr{45});
    REQUIRE(s4.id() == s1.id() + 3);
}

TEST_CASE("Can find BreakpointSite", "[breakpoint]")
{
    auto proc         = pdb::Process::launch("targets/run_endlessly");
    const auto& cproc = proc;

    proc->createBreakpointSite(pdb::VirtAddr{42});
    proc->createBreakpointSite(pdb::VirtAddr{43});
    proc->createBreakpointSite(pdb::VirtAddr{44});
    proc->createBreakpointSite(pdb::VirtAddr{45});

    auto& s1 = proc->breakpointSites().getByAddress(pdb::VirtAddr{44});
    REQUIRE(proc->breakpointSites().containsAddress(pdb::VirtAddr{44}));
    REQUIRE(s1.address().addr() == 44);

    auto& cs1 = cproc->breakpointSites().getByAddress(pdb::VirtAddr{44});
    REQUIRE(cproc->breakpointSites().containsAddress(pdb::VirtAddr{44}));
    REQUIRE(cs1.address().addr() == 44);

    auto& s2 = proc->breakpointSites().getById(s1.id() + 1);
    REQUIRE(proc->breakpointSites().containsId(s1.id() + 1));
    REQUIRE(s2.id() == s1.id() + 1);
    REQUIRE(s2.address().addr() == 45);

    auto& cs2 = cproc->breakpointSites().getById(cs1.id() + 1);
    REQUIRE(cproc->breakpointSites().containsId(cs1.id() + 1));
    REQUIRE(cs2.id() == cs1.id() + 1);
    REQUIRE(cs2.address().addr() == 45);
}

TEST_CASE("Cannot find BreakpointSite", "[breakpoint]")
{
    auto proc         = pdb::Process::launch("targets/run_endlessly");
    const auto& cproc = proc;

    REQUIRE_THROWS_AS(proc->breakpointSites().getByAddress(pdb::VirtAddr{44}), pdb::Error);
    REQUIRE_THROWS_AS(proc->breakpointSites().getById(44), pdb::Error);
    REQUIRE_THROWS_AS(cproc->breakpointSites().getByAddress(pdb::VirtAddr{44}), pdb::Error);
    REQUIRE_THROWS_AS(cproc->breakpointSites().getById(44), pdb::Error);
}

TEST_CASE("BreakpointSite list size and emptiness", "[breakpoint]")
{
    auto proc         = pdb::Process::launch("targets/run_endlessly");
    const auto& cproc = proc;

    REQUIRE(proc->breakpointSites().empty());
    REQUIRE(proc->breakpointSites().size() == 0);
    REQUIRE(cproc->breakpointSites().empty());
    REQUIRE(cproc->breakpointSites().size() == 0);

    proc->createBreakpointSite(pdb::VirtAddr{42});
    REQUIRE(!proc->breakpointSites().empty());
    REQUIRE(proc->breakpointSites().size() == 1);
    REQUIRE(!cproc->breakpointSites().empty());
    REQUIRE(cproc->breakpointSites().size() == 1);

    proc->createBreakpointSite(pdb::VirtAddr{45});
    REQUIRE(!proc->breakpointSites().empty());
    REQUIRE(proc->breakpointSites().size() == 2);
    REQUIRE(!cproc->breakpointSites().empty());
    REQUIRE(cproc->breakpointSites().size() == 2);
}

TEST_CASE("Can iterate BreakpointSite", "[breakpoint]")
{
    auto proc         = pdb::Process::launch("targets/run_endlessly");
    const auto& cproc = proc;

    proc->createBreakpointSite(pdb::VirtAddr{42});
    proc->createBreakpointSite(pdb::VirtAddr{43});
    proc->createBreakpointSite(pdb::VirtAddr{44});
    proc->createBreakpointSite(pdb::VirtAddr{45});

    proc->breakpointSites().forEach(
        [addr = 42](auto& site) mutable { REQUIRE(site.address().addr() == addr++); });
    cproc->breakpointSites().forEach(
        [addr = 42](auto& site) mutable { REQUIRE(site.address().addr() == addr++); });
}

TEST_CASE("Breakpoint on address works", "[breakpoint]")
{
    bool closeOnExec = false;
    pdb::Pipe channel(closeOnExec);

    auto proc = pdb::Process::launch("targets/hello_pdb", true, channel.getWrite());
    channel.closeWrite();

    auto offset      = getEntryPointOffset("targets/hello_pdb");
    auto loadAddress = getLoadAddress(proc->pid(), offset);

    proc->createBreakpointSite(loadAddress).enable();
    proc->resume();
    auto reason = proc->waitOnSignal();

    REQUIRE(reason.reason == pdb::ProcessState::Stopped);
    REQUIRE(reason.info == SIGTRAP);
    REQUIRE(proc->getProgramCounter() == loadAddress);

    proc->resume();
    reason = proc->waitOnSignal();

    REQUIRE(reason.reason == pdb::ProcessState::Exited);
    REQUIRE(reason.info == 0);

    auto data = channel.read();
    REQUIRE(pdb::toStringView(data) == "Hello world!\n");
}

TEST_CASE("Can remove BreakpointSite", "[breakpoint]")
{
    auto proc = pdb::Process::launch("targets/run_endlessly");

    auto& site = proc->createBreakpointSite(pdb::VirtAddr{42});
    proc->createBreakpointSite(pdb::VirtAddr{43});
    REQUIRE(proc->breakpointSites().size() == 2);

    proc->breakpointSites().removeById(site.id());
    proc->breakpointSites().removeByAddress(pdb::VirtAddr{43});
    REQUIRE(proc->breakpointSites().empty());
}

TEST_CASE("Reading and writing memory works", "[memory]")
{
    bool closeOnExec = false;
    pdb::Pipe channel(closeOnExec);
    auto proc = pdb::Process::launch("targets/memory", true, channel.getWrite());
    channel.closeWrite();

    proc->resume();
    proc->waitOnSignal();

    auto aPointer = pdb::fromBytes<uint64_t>(channel.read().data());
    auto dataVec  = proc->readMemory(pdb::VirtAddr{aPointer}, 8);
    auto data     = pdb::fromBytes<uint64_t>(dataVec.data());
    REQUIRE(data == 0xcafecafe);

    proc->resume();
    proc->waitOnSignal();

    auto bPointer = pdb::fromBytes<uint64_t>(channel.read().data());
    proc->writeMemory(pdb::VirtAddr{bPointer}, {pdb::asBytes("Hello, pdb!"), 12});

    proc->resume();
    proc->waitOnSignal();

    auto read = channel.read();
    REQUIRE(pdb::toStringView(read) == "Hello, pdb!");
}

TEST_CASE("Hardware breakpoint evades memory checksums", "[breakpoint]")
{
    bool closeOnExec = false;
    pdb::Pipe channel(closeOnExec);

    auto proc = pdb::Process::launch("targets/anti_debugger", true, channel.getWrite());
    channel.closeWrite();

    proc->resume();
    proc->waitOnSignal();

    auto func  = pdb::VirtAddr{pdb::fromBytes<uint64_t>(channel.read().data())};
    auto& soft = proc->createBreakpointSite(func, false);
    soft.enable();

    proc->resume();
    proc->waitOnSignal();

    REQUIRE(pdb::toStringView(channel.read()) == "Putting peperoni on pizza...\n");

    proc->breakpointSites().removeById(soft.id());
    auto& hard = proc->createBreakpointSite(func, true);
    hard.enable();

    proc->resume();
    proc->waitOnSignal();

    REQUIRE(proc->getProgramCounter() == func);

    proc->resume();
    proc->waitOnSignal();

    REQUIRE(pdb::toStringView(channel.read()) == "Putting mushrooms on pizza...\n");
}

TEST_CASE("Watchpoint detects read", "[watchpoint]")
{
    bool closeOnExec = false;
    pdb::Pipe channel(closeOnExec);

    auto proc = pdb::Process::launch("targets/anti_debugger", true, channel.getWrite());
    channel.closeWrite();

    proc->resume();
    proc->waitOnSignal();

    auto func = pdb::VirtAddr{pdb::fromBytes<uint64_t>(channel.read().data())};

    auto& watch = proc->createWatchpoint(func, pdb::StoppointMode::ReadWrite, 1);
    watch.enable();

    proc->resume();
    proc->waitOnSignal();

    proc->stepInstruction();
    auto& soft = proc->createBreakpointSite(func, false);
    soft.enable();

    proc->resume();
    auto reason = proc->waitOnSignal();
    REQUIRE(reason.info == SIGTRAP);

    proc->resume();
    proc->waitOnSignal();

    REQUIRE(pdb::toStringView(channel.read()) == "Putting mushrooms on pizza...\n");
}

TEST_CASE("Syscall mapping works", "[syscall]")
{
    REQUIRE(pdb::syscallIdToName(0) == "read");
    REQUIRE(pdb::syscallNameToId("read") == 0);
    REQUIRE(pdb::syscallIdToName(62) == "kill");
    REQUIRE(pdb::syscallNameToId("kill") == 62);
}

TEST_CASE("Syscall catchpoint work", "[catchpoint]")
{
    auto devNull = open("/dev/null", O_WRONLY);
    auto proc = pdb::Process::launch("targets/anti_debugger", true, devNull);

    auto writeSyscall = pdb::syscallNameToId("write");
    auto policy = pdb::SyscallCatchPolicy::catchSome({writeSyscall});
    proc->setSyscallCatchPolicy(policy);

    proc->resume();
    auto reason = proc->waitOnSignal();

    REQUIRE(reason.reason == pdb::ProcessState::Stopped);
    REQUIRE(reason.info == SIGTRAP);
    REQUIRE(reason.trapReason == pdb::TrapType::Syscall);
    REQUIRE(reason.syscallInfo->id == writeSyscall);
    REQUIRE(reason.syscallInfo->entry == true);

    proc->resume();
    reason = proc->waitOnSignal();

    REQUIRE(reason.reason == pdb::ProcessState::Stopped);
    REQUIRE(reason.info == SIGTRAP);
    REQUIRE(reason.trapReason == pdb::TrapType::Syscall);
    REQUIRE(reason.syscallInfo->id == writeSyscall);
    REQUIRE(reason.syscallInfo->entry == false);

    close(devNull);
}

TEST_CASE("ELF parser works", "[elf]")
{
    auto path = "targets/hello_pdb";
    pdb::Elf elf(path);
    auto entry = elf.header().e_entry;
    auto sym = elf.getSymbolAtAddress(pdb::FileAddr{elf, entry});
    auto name = elf.getString(sym.value()->st_name);
    REQUIRE(name == "_start");

    auto syms = elf.getSymbolsByName("_start");
    name = elf.getString(syms.at(0)->st_name);
    REQUIRE(name == "_start");

    elf.notifyLoaded(pdb::VirtAddr{0xcafecafe});
    sym = elf.getSymbolAtAddress(pdb::VirtAddr{0xcafecafe + entry});
    name = elf.getString(sym.value()->st_name);
    REQUIRE(name == "_start");
}
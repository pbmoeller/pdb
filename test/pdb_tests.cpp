#include <libpdb/bit.hpp>
#include <libpdb/error.hpp>
#include <libpdb/pipe.hpp>
#include <libpdb/process.hpp>
#include <libpdb/registers.hpp>

#include <catch2/catch_test_macros.hpp>

#include <sys/types.h>
#include <signal.h>

#include <fstream>
#include <string>

namespace {

bool processExists(pid_t pid) {
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
    auto proc = pdb::Process::attach(target->pid());
    REQUIRE(getProcessStatus(target->pid()) == 't');
}

TEST_CASE("Process::attach invalid PID", "[Process]") {
    REQUIRE_THROWS_AS(pdb::Process::attach(0), pdb::Error);
}

TEST_CASE("Process::resume success", "[Process]")
{
    {
        auto proc = pdb::Process::launch("targets/run_endlessly");
        proc->resume();
        auto status = getProcessStatus(proc->pid());
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

TEST_CASE("Write register works", "[register]") {
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



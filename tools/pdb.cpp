#include <libpdb/breakpoint_site.hpp>
#include <libpdb/disassembler.hpp>
#include <libpdb/error.hpp>
#include <libpdb/parse.hpp>
#include <libpdb/process.hpp>
#include <libpdb/syscalls.hpp>
#include <libpdb/target.hpp>

#include <editline/readline.h>

#include <csignal>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <memory>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

pdb::Process* g_pdbProcess{nullptr};

void handleSigint(int)
{
    kill(g_pdbProcess->pid(), SIGSTOP);
}

std::unique_ptr<pdb::Target> attach(int argc, char** argv)
{
    // Passing PID
    if(argc == 3 && argv[1] == std::string_view("-p")) {
        pid_t pid = std::atoi(argv[2]);
        return pdb::Target::attach(pid);
    }

    // Passing program name
    auto programPath = argv[1];
    auto target      = pdb::Target::launch(programPath);
    std::cout << "Launched process with PID " << target->getProcess().pid() << '\n';
    return target;
}

void printDisassembly(pdb::Process& process, pdb::VirtAddr address, size_t instructionCount)
{
    pdb::Disassembler dis(process);
    auto instructions = dis.disassemble(instructionCount, address);
    for(auto& inst : instructions) {
        std::cout << std::format("{:#018x}: {}\n", inst.address.addr(), inst.text);
    }
}

void printSource(const std::filesystem::path& path, uint64_t line, uint64_t nLinesContext)
{
    std::ifstream file{path.string()};
    auto startLine = line <= nLinesContext ? 1 : line - nLinesContext;
    auto endLine   = line + nLinesContext + 1;

    char c{};
    auto currentLine = 1u;
    while(currentLine != startLine && file.get(c)) {
        if(c == '\n') {
            ++currentLine;
        }
    }

    auto printLineStart = [&](auto currentLine) {
        auto fillWidth = static_cast<int>(std::floor(std::log10(endLine))) + 1;
        auto arrow     = currentLine == line ? ">" : " ";
        std::cout << std::format("{} {:>{}} ", arrow, currentLine, fillWidth);
    };

    printLineStart(currentLine);
    while(currentLine <= endLine && file.get(c)) {
        std::cout << c;
        if(c == '\n') {
            ++currentLine;
            printLineStart(currentLine);
        }
    }

    std::cout << std::endl;
}

std::vector<std::string> split(std::string_view str, char delimiter)
{
    std::vector<std::string> result{};
    std::stringstream ss{std::string(str)};
    std::string item;

    while(std::getline(ss, item, delimiter)) {
        result.push_back(item);
    }
    return result;
}

bool isPrefix(std::string_view str, std::string_view prefix)
{
    if(str.size() > prefix.size()) {
        return false;
    }
    return std::equal(str.begin(), str.end(), prefix.begin());
}

template<std::ranges::input_range R>
std::string formatHexJoin(std::string_view format, const R& r)
{
    std::stringstream out;
    out << "[";
    bool first = true;
    for(auto v : r) {
        if(!first) {
            out << ",";
        }
        first = false;

        if constexpr(std::is_same_v<std::remove_cvref_t<decltype(v)>, std::byte>) {
            auto uv = std::to_integer<unsigned>(v);
            out << std::vformat(format, std::make_format_args(uv));
        } else {
            out << std::vformat(format, std::make_format_args(v));
        }
    }

    out << "]";
    return out.str();
}

std::string getSigtrapInfo(const pdb::Process& process, pdb::StopReason reason)
{
    if(reason.trapReason == pdb::TrapType::SoftwareBreak) {
        auto& site = process.breakpointSites().getByAddress(process.getProgramCounter());
        return std::format(" (breakpoint {})", site.id());
    }
    if(reason.trapReason == pdb::TrapType::HardwareBreak) {
        auto id = process.getCurrentHardwareStoppoint();

        if(id.index() == 0) {
            return std::format(" (breakpoint {})", std::get<0>(id));
        }

        std::string message;
        auto& point = process.watchpoints().getById(std::get<1>(id));
        message += std::format(" (watchpoint {})", point.id());

        if(point.data() == point.previousData()) {
            message += std::format("\nValue: {:#x}", point.data());
        } else {
            message += std::format("\nOld value: {:#x}\nNew value: {:#x}", point.previousData(),
                                   point.data());
        }
        return message;
    }
    if(reason.trapReason == pdb::TrapType::SingleStep) {
        return " (single step)";
    }
    if(reason.trapReason == pdb::TrapType::Syscall) {
        const auto& info    = *reason.syscallInfo;
        std::string message = " ";
        if(info.entry) {
            message += "(syscall entry)\n";
            message += std::format("syscall: {}({})", pdb::syscallIdToName(info.id),
                                   formatHexJoin("{:#x}", info.args));
        } else {
            message += "(syscall exit)\n";
            message += std::format("syscall returned: {:#x}", info.ret);
        }
        return message;
    }

    return "";
}

std::string getSignalStopReason(const pdb::Target& target, pdb::StopReason reason)
{
    auto& process = target.getProcess();
    auto pc       = process.getProgramCounter();
    std::string message =
        std::format("stopped with signal {} at {:#x}", sigabbrev_np(reason.info), pc.addr());

    auto line = target.lineEntryAtPc();
    if(line != pdb::LineTable::Iterator()) {
        auto file = line->fileEntry->path.filename().string();
        message += std::format(", {}:{}", file, line->line);
    }

    auto funcName = target.functionNameAtAddress(pc);
    if(funcName != "") {
        message += std::format(" ({})", funcName);
    }

    if(reason.info == SIGTRAP) {
        message += getSigtrapInfo(process, reason);
    }
    return message;
}

} // namespace

void printStopReason(const pdb::Target& target, const pdb::StopReason& reason)
{
    std::string message;

    switch(reason.reason) {
        case pdb::ProcessState::Stopped:
        {
            message = getSignalStopReason(target, reason);
            break;
        }
        case pdb::ProcessState::Exited:
            message = std::format("Exited with status {}", static_cast<int>(reason.info));
            break;
        case pdb::ProcessState::Terminated:
            message = std::format("Terminated with signal {}", sigabbrev_np(reason.info));
            break;
        default:
            break;
    }

    std::cout << std::format("Process {} {}", target.getProcess().pid(), message) << std::endl;
}

void printCodeLocation(pdb::Target& target)
{
    if(target.getStack().hasFrames()) {
        auto& frame = target.getStack().currentFrame();
        printSource(frame.location.file->path, frame.location.line, 3);
    } else {
        printDisassembly(target.getProcess(), target.getProcess().getProgramCounter(), 5);
    }
}

void handleStop(pdb::Target& target, pdb::StopReason reason)
{
    printStopReason(target, reason);
    if(reason.reason == pdb::ProcessState::Stopped) {
        printCodeLocation(target);
    }
}

void printHelp(const std::vector<std::string>& args)
{
    if(args.size() == 1) {
        std::cerr << R"(Available commands
    breakpoint  - Commands for operating on breakpoints
    catchpoint  - Commands for operating on catchpoints
    continue    - Resume the process
    disassemble - Disassemble machine code to assembly
    down        - Select the stack frame below current one
    finish      - Step-out
    memory      - Operations on memory
    next        - Step-over
    register    - Commands for operating on registers
    step        - Step-in
    stepi       - Single instruction step
    up          - Select the stack frame above current one
    watchpoint  - Commands for operating on watchpoints
)";
    } else if(isPrefix(args[1], "register")) {
        std::cerr << R"(Available commands
    read
    read <register>
    read all
    write <register> <value>
)";
    } else if(isPrefix(args[1], "breakpoint")) {
        std::cerr << R"(Available commands
    list
    delete <id>
    disable <id>
    enable <id>
    set <address>
    set <address> - h
)";
    } else if(isPrefix(args[1], "memory")) {
        std::cerr << R"(Available commands
    read <address>
    read <address> <number of bytes>
    write <address> <bytes>
)";
    } else if(isPrefix(args[1], "disassemble")) {
        std::cerr << R"(Available commands
    -c <number of instructions>
    -a <start address>
)";
    } else if(isPrefix(args[1], "watchpoint")) {
        std::cerr << R"(Available commands
    list
    delete <id>
    disable <id>
    enable <id>
    set <address> <write|rw|execute> <size>
)";
    } else if(isPrefix(args[1], "catchpoint")) {
        std::cerr << R"(Available commands
    syscall
    syscall none
    syscall <list of syscall ID's or names>
)";
    } else {
        std::cerr << "No help available on that\n";
    }
}

void printBacktrace(const pdb::Target& target)
{
    auto& stack = target.getStack();
    auto i      = 0;
    for(auto& frame : stack.frames()) {
        auto pc       = frame.backtraceReportAddress;
        auto funcName = target.functionNameAtAddress(pc);

        std::string message = i == stack.currentFrameIndex() ? "*" : " ";
        message += std::format("[{}]: {:#x} {}", i++, pc.addr(), funcName);
        if(frame.inlined) {
            message += std::format(" [inlined] {}", *frame.funcDie.name());
        }
        std::cout << message << "\n";
    }

    std::cout.flush();
}

void handleRegisterRead(pdb::Target& target, const std::vector<std::string>& args)
{
    auto format = [](auto t) {
        if constexpr(std::is_floating_point_v<decltype(t)>) {
            return std::format("{}", t);
        } else if constexpr(std::is_integral_v<decltype(t)>) {
            return std::format("{:#0{}x}", t, sizeof(t) * 2 + 2);
        } else {
            return formatHexJoin("{:#04x}", t);
        }
    };

    auto& regs              = target.getStack().regs();
    auto printRegisterValue = [&](auto info) {
        if(regs.isUndefined(info.id)) {
            std::cout << std::format("{}:\tundefined\n", info.name);
        } else {
            auto value = regs.read(info);
            std::cout << std::format("{}:\t{}\n", info.name, std::visit(format, value));
        }
    };

    if(args.size() == 2 || (args.size() == 3 && args[2] == "all")) {
        for(auto& info : pdb::g_registerInfos) {
            if(args.size() == 3 || info.type == pdb::RegisterType::GPR) {
                printRegisterValue(info);
            }
        }
    } else if(args.size() == 3) {
        try {
            auto info = pdb::registerInfoByName(args[2]);
            printRegisterValue(info);
        } catch(pdb::Error& err) {
            std::cerr << "No such register\n";
            return;
        }
    } else {
        printHelp({"help", "register"});
    }
}

pdb::Registers::Value parseRegisterValue(pdb::RegisterInfo info, std::string_view text)
{
    try {
        if(info.format == pdb::RegisterFormat::UINT) {
            switch(info.size) {
                case 1:
                    return pdb::toIntegral<uint8_t>(text, 16).value();
                case 2:
                    return pdb::toIntegral<uint16_t>(text, 16).value();
                case 4:
                    return pdb::toIntegral<uint32_t>(text, 16).value();
                case 8:
                    return pdb::toIntegral<uint64_t>(text, 16).value();
            }
        } else if(info.format == pdb::RegisterFormat::DOUBLE_FLOAT) {
            return pdb::toFloat<double>(text).value();
        } else if(info.format == pdb::RegisterFormat::LONG_DOUBLE) {
            return pdb::toFloat<long double>(text).value();
        } else if(info.format == pdb::RegisterFormat::VECTOR) {
            if(info.size == 8) {
                return pdb::parseVector<8>(text);
            } else if(info.size == 16) {
                return pdb::parseVector<16>(text);
            }
        }
    } catch(...) {
        ;
    }

    pdb::Error::send("Invalid format");
}

void handleRegisterWrite(pdb::Process& process, const std::vector<std::string>& args)
{
    if(args.size() != 4) {
        printHelp({"help", "register"});
        return;
    }
    try {
        auto info  = pdb::registerInfoByName(args[2]);
        auto value = parseRegisterValue(info, args[3]);
        process.getRegisters().write(info, value);
    } catch(pdb::Error& err) {
        std::cerr << err.what() << '\n';
        return;
    }
}

void handleRegisterCommand(pdb::Target& target, const std::vector<std::string>& args)
{
    if(args.size() < 2) {
        printHelp({"help", "register"});
        return;
    }

    if(isPrefix(args[1], "read")) {
        handleRegisterRead(target, args);
    } else if(isPrefix(args[1], "write")) {
        handleRegisterWrite(target.getProcess(), args);
    } else {
        printHelp(args);
    }
}

void handleBreakpointListCommand(pdb::Target& target)
{
    if(target.breakpoints().empty()) {
        std::cout << "No breakpoints set\n";
    } else {
        std::cout << "Current Breakpoints:\n";
        target.breakpoints().forEach([](auto& bp) {
            if(bp.isInternal()) {
                return;
            }
            std::cout << bp.id() << ": ";
            if(auto funcBp = dynamic_cast<pdb::FunctionBreakpoint*>(&bp)) {
                std::cout << "function = " << funcBp->functionName();
            } else if(auto lineBp = dynamic_cast<pdb::LineBreakpoint*>(&bp)) {
                std::cout << "file = " << lineBp->file() << ", line = " << lineBp->line();
            } else if(auto addrBp = dynamic_cast<pdb::AddressBreakpoint*>(&bp)) {
                std::cout << std::format("address = {:#x}", addrBp->address().addr());
            }
            std::cout << ", " << (bp.isEnabled() ? "enabled" : "disabled") << ":\n";
            bp.breakpointSites().forEach([&](auto& site) {
                std::cout << std::format("    .{}: address = {:#x}, {}\n", site.id(),
                                         site.address().addr(),
                                         site.isEnabled() ? "enabled" : "disabled");
            });
        });
    }
}

void handleBreakpointSetCommand(pdb::Target& target, const std::vector<std::string>& args)
{
    bool hardware = false;
    if(args.size() == 4) {
        if(args[3] == "-h") {
            hardware = true;
        } else {
            pdb::Error::send("Invalid breakpoint command argument");
        }
    }
    if(args[2].find("0x") == 0) {
        auto address = pdb::toIntegral<uint64_t>(args[2], 16);
        if(!address) {
            std::cerr << "Breakpoint command expects address in hexadecimal, prefixed with '0x'"
                      << std::endl;
        }
        target.createAddressBreakpoint(pdb::VirtAddr{*address}, hardware).enable();
    } else if(args[2].find(':') != std::string::npos) {
        auto data = split(args[2], ':');
        auto path = data[0];
        auto line = pdb::toIntegral<uint64_t>(data[1]);
        if(!line) {
            std::cerr << "Line number should be an integer" << std::endl;
            return;
        }
        target.createLineBreakpoint(path, *line, hardware).enable();
    } else {
        target.createFunctionBreakpoint(args[2]).enable();
    }
}

void handleBreakpointToggle(pdb::Target& target, const std::vector<std::string>& args)
{
    auto command = args[1];

    auto dotPos = args[2].find('.');
    auto idStr  = args[2].substr(0, dotPos);
    auto id     = pdb::toIntegral<pdb::Breakpoint::IdType>(idStr);
    if(!id) {
        std::cerr << "Command expects breakpoint id";
        return;
    }
    auto& bp = target.breakpoints().getById(*id);

    if(dotPos != std::string::npos) {
        auto siteIdStr = args[2].substr(dotPos + 1);
        auto siteId    = pdb::toIntegral<pdb::Breakpoint::IdType>(siteIdStr);
        if(!siteId) {
            std::cerr << "Command expects breakpoint site id";
            return;
        }
        if(isPrefix(command, "enable")) {
            bp.breakpointSites().getById(*siteId).enable();
        } else if(isPrefix(command, "disable")) {
            bp.breakpointSites().getById(*siteId).disable();
        }
    } else if(isPrefix(command, "enable")) {
        bp.enable();
    } else if(isPrefix(command, "disable")) {
        bp.disable();
    } else if(isPrefix(command, "delete")) {
        bp.breakpointSites().forEach([&](auto& site) {
            target.getProcess().breakpointSites().removeByAddress(site.address());
        });
        target.breakpoints().removeById(*id);
    }
}

void handleBreakpointCommand(pdb::Target& target, const std::vector<std::string>& args)
{
    if(args.size() < 2) {
        printHelp({"help", "breakpoint"});
        return;
    }

    auto command = args[1];
    if(isPrefix(command, "list")) {
        handleBreakpointListCommand(target);
        return;
    }

    if(args.size() < 3) {
        printHelp({"help", "breakpoint"});
        return;
    }

    if(isPrefix(command, "set")) {
        handleBreakpointSetCommand(target, args);
        return;
    }

    handleBreakpointToggle(target, args);
}

void handleMemoryReadCommand(pdb::Process& process, const std::vector<std::string>& args)
{
    auto address = pdb::toIntegral<uint64_t>(args[2], 16);
    if(!address) {
        pdb::Error::send("Invalid address format");
    }

    auto nBytes = 32;
    if(args.size() == 4) {
        auto bytesArg = pdb::toIntegral<size_t>(args[3]);
        if(!bytesArg) {
            pdb::Error::send("invalid number of bytes");
        }
        nBytes = *bytesArg;
    }

    auto data = process.readMemory(pdb::VirtAddr{*address}, nBytes);

    for(size_t i = 0; i < data.size(); i += 16) {
        auto start = data.begin() + i;
        auto end   = data.begin() + std::min(i + 16, data.size());

        auto line = formatHexJoin("{:02x}", std::ranges::subrange(start, end));
        std::cout << std::format("{:#016x}: {}\n", *address + i, line);
    }
}

void handleMemoryWriteCommand(pdb::Process& process, const std::vector<std::string>& args)
{
    if(args.size() != 4) {
        printHelp({"help", "memory"});
        return;
    }

    auto address = pdb::toIntegral<uint64_t>(args[2], 16);
    if(!address) {
        pdb::Error::send("invalid address format");
    }

    auto data = pdb::parseVector(args[3]);
    process.writeMemory(pdb::VirtAddr{*address}, {data.data(), data.size()});
}

void handleMemoryCommand(pdb::Process& process, const std::vector<std::string>& args)
{
    if(args.size() < 3) {
        printHelp({"help", "memory"});
        return;
    }
    if(isPrefix(args[1], "read")) {
        handleMemoryReadCommand(process, args);
    } else if(isPrefix(args[1], "write")) {
        handleMemoryWriteCommand(process, args);

    } else {
        printHelp({"help", "memory"});
    }
}

void handleDisassembleCommand(pdb::Process& process, const std::vector<std::string>& args)
{
    auto address            = process.getProgramCounter();
    size_t instructionCount = 5;

    auto it = args.begin() + 1;
    while(it != args.end()) {
        if(*it == "-a" && it + 1 != args.end()) {
            ++it;
            auto optAddr = pdb::toIntegral<uint64_t>(*it++, 16);
            if(!optAddr) {
                pdb::Error::send("Invalid address format");
            }
            address = pdb::VirtAddr{*optAddr};
        } else if(*it == "-c" && it + 1 != args.end()) {
            ++it;
            auto optN = pdb::toIntegral<size_t>(*it++);
            if(!optN) {
                pdb::Error::send("Invalid isntruction count");
            }
            instructionCount = *optN;
        } else {
            printHelp({"help", "disassemble"});
            return;
        }
    }
    printDisassembly(process, address, instructionCount);
}

void handleWatchpointList(pdb::Process& process, const std::vector<std::string>& args)
{
    auto stoppointModeToString = [](auto mode) {
        switch(mode) {
            case pdb::StoppointMode::Execute:
                return "Execute";
            case pdb::StoppointMode::Write:
                return "Write";
            case pdb::StoppointMode::ReadWrite:
                return "ReadWrite";
            default:
                pdb::Error::send("Invalid stoppoint mode");
        }
    };

    if(process.watchpoints().empty()) {
        std::cout << "No watchpoints set\n";
    } else {
        std::cout << "Current watchpoints:\n";
        process.watchpoints().forEach([&](auto& point) {
            std::cout << std::format("{}: address = {:#x}, mode = {}, size = {}, {}\n", point.id(),
                                     point.address().addr(), stoppointModeToString(point.mode()),
                                     point.size(), point.isEnabled() ? "enabled" : "disabled");
        });
    }
}

void handleWatchpointSet(pdb::Process& process, const std::vector<std::string>& args)
{
    if(args.size() != 5) {
        printHelp({"help", "watchpoint"});
        return;
    }
    auto address  = pdb::toIntegral<uint64_t>(args[2], 16);
    auto modeText = args[3];
    auto size     = pdb::toIntegral<size_t>(args[4]);

    if(!address || !size || !(modeText == "write" || modeText == "rw" || modeText == "execute")) {
        printHelp({"help", "watchpoint"});
        return;
    }

    pdb::StoppointMode mode;
    if(modeText == "write") {
        mode = pdb::StoppointMode::Write;
    } else if(modeText == "rw") {
        mode = pdb::StoppointMode::ReadWrite;
    } else if(modeText == "execute") {
        mode = pdb::StoppointMode::Execute;
    }

    process.createWatchpoint(pdb::VirtAddr{*address}, mode, *size).enable();
}

void handleWatchpointCommand(pdb::Process& process, const std::vector<std::string>& args)
{
    if(args.size() < 2) {
        printHelp({"help", "watchpoint"});
        return;
    }

    auto command = args[1];

    if(isPrefix(command, "list")) {
        handleWatchpointList(process, args);
        return;
    }
    if(isPrefix(command, "set")) {
        handleWatchpointSet(process, args);
        return;
    }

    if(args.size() < 3) {
        printHelp({"help", "watchpoint"});
        return;
    }

    auto id = pdb::toIntegral<pdb::Watchpoint::IdType>(args[2]);
    if(!id) {
        std::cerr << "Command expects watchpoint id";
        return;
    }

    if(isPrefix(command, "enable")) {
        process.watchpoints().getById(*id).enable();
    } else if(isPrefix(command, "disable")) {
        process.watchpoints().getById(*id).disable();
    } else if(isPrefix(command, "delete")) {
        process.watchpoints().removeById(*id);
    }
}

void handleSyscallCatchpointCommand(pdb::Process& process, const std::vector<std::string>& args)
{
    pdb::SyscallCatchPolicy policy{pdb::SyscallCatchPolicy::catchAll()};

    if(args.size() == 3 && args[2] == "none") {
        policy = pdb::SyscallCatchPolicy::catchNone();
    } else if(args.size() >= 3) {
        auto syscalls = split(args[2], ',');
        std::vector<int> toCatch;
        std::transform(std::begin(syscalls), std::end(syscalls), std::back_inserter(toCatch),
                       [](auto& syscall) {
                           return std::isdigit(syscall[0]) ? pdb::toIntegral<int>(syscall).value()
                                                           : pdb::syscallNameToId(syscall);
                       });
        policy = pdb::SyscallCatchPolicy::catchSome(std::move(toCatch));
    }
    process.setSyscallCatchPolicy(policy);
}

void handleCatchpointCommand(pdb::Process& process, const std::vector<std::string>& args)
{
    if(args.size() < 2) {
        printHelp({"help", "catchpoint"});
        return;
    }
    if(isPrefix(args[1], "syscall")) {
        handleSyscallCatchpointCommand(process, args);
    }
}

void handleCommand(std::unique_ptr<pdb::Target>& target, std::string_view line)
{
    auto args    = split(line, ' ');
    auto command = args[0];
    auto process = &target->getProcess();

    if(isPrefix(command, "continue")) {
        process->resume();
        auto reason = process->waitOnSignal();
        handleStop(*target, reason);
    } else if(isPrefix(command, "help")) {
        printHelp(args);
    } else if(isPrefix(command, "register")) {
        handleRegisterCommand(*target, args);
    } else if(isPrefix(command, "breakpoint")) {
        handleBreakpointCommand(*target, args);
    } else if(isPrefix(command, "next")) {
        auto reason = target->stepOver();
        handleStop(*target, reason);
    } else if(isPrefix(command, "finish")) {
        auto reason = target->stepOut();
        handleStop(*target, reason);
    } else if(isPrefix(command, "step")) {
        auto reason = target->stepIn();
        handleStop(*target, reason);
    } else if(isPrefix(command, "stepi")) {
        auto reason = process->stepInstruction();
        handleStop(*target, reason);
    } else if(isPrefix(command, "memory")) {
        handleMemoryCommand(*process, args);
    } else if(isPrefix(command, "up")) {
        target->getStack().up();
        printCodeLocation(*target);
    } else if(isPrefix(command, "down")) {
        target->getStack().down();
        printCodeLocation(*target);
    } else if(isPrefix(command, "backtrace")) {
        printBacktrace(*target);
    } else if(isPrefix(command, "disassemble")) {
        handleDisassembleCommand(*process, args);
    } else if(isPrefix(command, "watchpoint")) {
        handleWatchpointCommand(*process, args);
    } else if(isPrefix(command, "catchpoint")) {
        handleCatchpointCommand(*process, args);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
    }
}

void mainLoop(std::unique_ptr<pdb::Target>& target)
{
    char* line = nullptr;
    while((line = readline("pdb> ")) != nullptr) {
        std::string lineStr;

        if(line == std::string_view("")) {
            free(line);
            if(history_length > 0) {
                lineStr = history_list()[history_length - 1]->line;
            }
        } else {
            lineStr = line;
            add_history(line);
            free(line);
        }

        if(!lineStr.empty()) {
            try {
                handleCommand(target, lineStr);
            } catch(const pdb::Error& e) {
                std::cerr << e.what() << "\n";
            }
        }
    }
}

int main(int argc, char** argv)
{
    if(argc == 1) {
        std::cerr << "No arguments provided.\n";
        return -1;
    }

    try {
        auto target  = attach(argc, argv);
        g_pdbProcess = &target->getProcess();
        signal(SIGINT, handleSigint);
        mainLoop(target);
    } catch(const pdb::Error& e) {
        std::cout << e.what() << '\n';
    }

    return 0;
}

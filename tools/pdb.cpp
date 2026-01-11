#include <libpdb/breakpoint_site.hpp>
#include <libpdb/disassembler.hpp>
#include <libpdb/error.hpp>
#include <libpdb/parse.hpp>
#include <libpdb/process.hpp>

#include <editline/readline.h>

#include <unistd.h>

#include <algorithm>
#include <format>
#include <iostream>
#include <memory>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::unique_ptr<pdb::Process> attach(int argc, char** argv)
{
    // Passing PID
    if(argc == 3 && argv[1] == std::string_view("-p")) {
        pid_t pid = std::atoi(argv[2]);
        return pdb::Process::attach(pid);
    }

    // Passing program name
    auto programPath = argv[1];
    auto proc        = pdb::Process::launch(programPath);
    std::cout << "Launched process with PID " << proc->pid() << '\n';
    return proc;
}

void printDisassembly(pdb::Process& process, pdb::VirtAddr address, size_t instructionCount)
{
    pdb::Disassembler dis(process);
    auto instructions = dis.disassemble(instructionCount, address);
    for(auto& inst : instructions) {
        std::cout << std::format("{:#018x}: {}\n", inst.address.addr(), inst.text);
    }
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

} // namespace

void printStopReason(const pdb::Process& process, const pdb::StopReason& reason)
{
    std::string message;

    switch(reason.reason) {
        case pdb::ProcessState::Stopped:
            message = std::format("Stopped with signal {} at {:#x}", sigabbrev_np(reason.info),
                                  process.getProgramCounter().addr());
            break;
        case pdb::ProcessState::Exited:
            message = std::format("Exited with status {}", static_cast<int>(reason.info));
            break;
        case pdb::ProcessState::Terminated:
            message = std::format("Terminated with signal {}", sigabbrev_np(reason.info));
            break;
        default:
            break;
    }

    std::cout << std::format("Process {} {}", process.pid(), message) << std::endl;
}

void handleStop(pdb::Process& process, pdb::StopReason reason)
{
    printStopReason(process, reason);
    if(reason.reason == pdb::ProcessState::Stopped) {
        printDisassembly(process, process.getProgramCounter(), 5);
    }
}

void printHelp(const std::vector<std::string>& args)
{
    if(args.size() == 1) {
        std::cerr << R"(Available commands
    breakpoint  - Commands for operating on breakpoints
    continue    - Resume the process
    disassemble - Disassemble machine code to assembly
    memory      - Operations on memory
    register    - Commands for operating on registers
    step        - Step over a single instruction
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
    } else {
        std::cerr << "No help available on that\n";
    }
}

void handleRegisterRead(pdb::Process& process, const std::vector<std::string>& args)
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

    if(args.size() == 2 || (args.size() == 3 && args[2] == "all")) {
        for(auto& info : pdb::g_registerInfos) {
            auto shouldPrint = (args.size() == 3 || info.type == pdb::RegisterType::GPR)
                            && info.name != "orig_rax";
            if(!shouldPrint) {
                continue;
            }
            auto value = process.getRegisters().read(info);
            std::cout << std::format("{}:\t{}\n", info.name, std::visit(format, value));
        }
    } else if(args.size() == 3) {
        try {
            auto info  = pdb::registerInfoByName(args[2]);
            auto value = process.getRegisters().read(info);
            std::cout << std::format("{}:\t{}\n", info.name, std::visit(format, value));
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

void handleRegisterCommand(pdb::Process& process, const std::vector<std::string>& args)
{
    if(args.size() < 2) {
        printHelp({"help", "register"});
        return;
    }

    if(isPrefix(args[1], "read")) {
        handleRegisterRead(process, args);
    } else if(isPrefix(args[1], "write")) {
        handleRegisterWrite(process, args);
    } else {
        printHelp(args);
    }
}

void handleBreakpointCommand(pdb::Process& process, const std::vector<std::string>& args)
{
    if(args.size() < 2) {
        printHelp({"help", "breakpoint"});
        return;
    }

    auto command = args[1];
    if(isPrefix(command, "list")) {
        if(process.breakpointSites().empty()) {
            std::cout << "No breakpoints set\n";
        } else {
            std::cout << "Current breakpoints:\n";
            process.breakpointSites().forEach([](auto& site) {
                if(site.isInternal()) {
                    return;
                }
                std::cout << std::format("{}: address = {:#x}, {}\n", site.id(),
                                         site.address().addr(),
                                         site.isEnabled() ? "enabled" : "disabled");
            });
        }
        return;
    }

    if(args.size() < 3) {
        printHelp({"help", "breakpoint"});
        return;
    }

    if(isPrefix(command, "set")) {
        auto address = pdb::toIntegral<uint64_t>(args[2], 16);

        if(!address) {
            std::cerr << "Breakpoint command expects address in hexadecimal, prefixed with '0x'\n";
            return;
        }

        bool hardware = false;
        if(args.size() == 4) {
            if(args[3] == "-h") {
                hardware = true;
            } else {
                pdb::Error::send("Invalid breakpoint command argument");
            }
        }

        process.createBreakpointSite(pdb::VirtAddr{*address}, hardware).enable();
        return;
    }

    auto id = pdb::toIntegral<pdb::BreakpointSite::IdType>(args[2]);
    if(!id) {
        std::cerr << "Command expects breakpoint id\n";
        return;
    }

    if(isPrefix(command, "enable")) {
        process.breakpointSites().getById(*id).enable();
    } else if(isPrefix(command, "disable")) {
        process.breakpointSites().getById(*id).disable();
    } else if(isPrefix(command, "delete")) {
        process.breakpointSites().removeById(*id);
    }
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

void handleCommand(std::unique_ptr<pdb::Process>& process, std::string_view line)
{
    auto args    = split(line, ' ');
    auto command = args[0];

    if(isPrefix(command, "continue")) {
        process->resume();
        auto reason = process->waitOnSignal();
        handleStop(*process, reason);
    } else if(isPrefix(command, "help")) {
        printHelp(args);
    } else if(isPrefix(command, "register")) {
        handleRegisterCommand(*process, args);
    } else if(isPrefix(command, "breakpoint")) {
        handleBreakpointCommand(*process, args);
    } else if(isPrefix(command, "step")) {
        auto reason = process->stepInstruction();
        handleStop(*process, reason);
    } else if(isPrefix(command, "memory")) {
        handleMemoryCommand(*process, args);
    } else if(isPrefix(command, "disassemble")) {
        handleDisassembleCommand(*process, args);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
    }
}

void mainLoop(std::unique_ptr<pdb::Process>& process)
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
                handleCommand(process, lineStr);
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
        auto process = attach(argc, argv);
        mainLoop(process);
    } catch(const pdb::Error& e) {
        std::cout << e.what() << '\n';
    }

    return 0;
}

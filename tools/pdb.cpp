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
    const char* programname = argv[1];
    return pdb::Process::launch(programname);
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
std::string formatHexJoin(std::string_view format, const R &r)
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

void printStopReason(const pdb::Process& process, const pdb::StopReason& reason)
{
    std::string message;

    switch(reason.reason) {
        case pdb::ProcessState::Stopped:
            message = std::format("Stopped with signal {} at {:#x}", sigabbrev_np(reason.info), process.getProgramCounter().addr());
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

void printHelp(const std::vector<std::string> &args)
{
    if(args.size() == 1) {
        std::cerr << R"(Available commands
    continue    - Resume the process
    register    - Commands for operating on registers
)";
    } else if(isPrefix(args[1], "register")) {
        std::cerr << R"(Available commands
    read
    read <register>
    read all
    write <register> <value>
)";
    } else {
        std::cerr << "No help available on that\n";
    }
}

void handleRegisterRead(pdb::Process &process, const std::vector<std::string> &args)
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
        for(auto &info : pdb::g_registerInfos) {
            auto shouldPrint = (args.size() == 3 || info.type == pdb::RegisterType::GPR) && info.name != "orig_rax";
            if(!shouldPrint) {
                continue;
            }
            auto value = process.getRegisters().read(info);
            std::cout << std::format("{}:\t{}\n", info.name, std::visit(format, value));
        }
    } else if(args.size() == 3) {
        try {
            auto info = pdb::registerInfoByName(args[2]);
            auto value = process.getRegisters().read(info);
            std::cout << std::format("{}:\t{}\n", info.name, std::visit(format, value));
        } catch(pdb::Error &err) {
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
            case 1: return pdb::toIntegral<uint8_t>(text, 16).value();
            case 2: return pdb::toIntegral<uint16_t>(text, 16).value();
            case 4: return pdb::toIntegral<uint32_t>(text, 16).value();
            case 8: return pdb::toIntegral<uint64_t>(text, 16).value();
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

void handleRegisterWrite(pdb::Process &process, const std::vector<std::string> &args)
{
    if(args.size() != 4) {
        printHelp({"help", "register"});
        return;
    }
    try {
        auto info = pdb::registerInfoByName(args[2]);
        auto value = parseRegisterValue(info, args[3]);
        process.getRegisters().write(info, value);
    } catch(pdb::Error &err) {
        std::cerr << err.what() << '\n';
        return;
    }
}

void handleRegister(pdb::Process &process, const std::vector<std::string> &args)
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

void handleCommand(std::unique_ptr<pdb::Process>& process, std::string_view line)
{
    auto args = split(line, ' ');
    auto command = args[0];

    if(isPrefix(command, "continue")) {
        process->resume();
        auto reason = process->waitOnSignal();
        printStopReason(*process, reason);
    } else if(isPrefix(command, "help")) {
        printHelp(args);
    } else if(isPrefix(command, "register")) {
        handleRegister(*process, args);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
    }
}

} // namespace

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

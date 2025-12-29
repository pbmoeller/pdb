#include <libpdb/error.hpp>
#include <libpdb/process.hpp>

#include <editline/readline.h>

#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <memory>
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

void printStopReason(const pdb::Process& process, const pdb::StopReason& reason)
{
    std::cout << "Process " << process.pid() << ' ';

    switch(reason.reason) {
        case pdb::ProcessState::Stopped:
            std::cout << "stopped with signal " << sigabbrev_np(reason.info) << "\n";
            break;
        case pdb::ProcessState::Exited:
            std::cout << "exited with status " << static_cast<int>(reason.info) << "\n";
            break;
        case pdb::ProcessState::Terminated:
            std::cout << "terminated with signal " << sigabbrev_np(reason.info) << "\n";
            break;
        default:
            break;
    }

    std::cout << std::endl;
}

void handleCommand(std::unique_ptr<pdb::Process>& process, std::string_view line)
{
    auto args    = split(line, ' ');
    auto command = args[0];

    if(isPrefix(command, "continue")) {
        process->resume();
        auto reason = process->waitOnSignal();
        printStopReason(*process, reason);
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

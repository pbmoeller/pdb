#include <cstdio>
#include <numeric>
#include <unistd.h>
#include <signal.h>

void anInnocentFunction() {
    std::puts("Putting mushrooms on pizza...");
}

void anInnocentFunctionEnd() {}

int checksum()
{
    auto start = reinterpret_cast<volatile const char*>(&anInnocentFunction);
    auto end = reinterpret_cast<volatile const char*>(&anInnocentFunctionEnd);
    return std::accumulate(start, end, 0);
}

int main() {
    auto safe = checksum();

    auto ptr = reinterpret_cast<void*>(&anInnocentFunction);
    write(STDOUT_FILENO, &ptr, sizeof(void*));
    fflush(stdout);
    raise(SIGTRAP);

    while(true) {
        sleep(1);
        if(checksum() == safe) {
            anInnocentFunction();
        } else {
            std::puts("Putting peperoni on pizza...");
        }

        fflush(stdout);
        raise(SIGTRAP);
    }

    return 0;
}
#include <cstdio>

__attribute__((always_inline))
inline void scratchEars() {
    std::puts("Scratching ears");
}

__attribute__((always_inline))
inline void petCat()
{
    scratchEars();
    std::puts("Done petting cat");
}

inline void findHappiness()
{
    petCat();
    std::puts("Found happiness");
}

int main() {
    findHappiness();
    findHappiness();
}
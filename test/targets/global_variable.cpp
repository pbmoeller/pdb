#include <cstdint>

uint64_t g_int = 0;

int main()
{
    g_int = 10;
    g_int = 42;
}

struct Cat
{
    const char* name;
    int age : 5;
    int color : 3;
};

struct Person
{
    const char* name;
    int age;
    Cat* pets;
    int numPets;
};

Cat marshmallow{"Marshmallow", 4, 1};
Cat lexicalCat{"Lexical Cat", 8, 2};
Cat milkshake{"Milkshake", 4, 3};
Cat cats[]{marshmallow, lexicalCat, milkshake};
Person sy{"Sy", 33, cats, 3};

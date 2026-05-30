#include <iostream>

struct Cat
{
    const char* name;
    void meow() const { std::cout << "meow\n"; }
};

int main()
{
    const char*(Cat::* dataPtr)  = &Cat::name;
    void (Cat::*funcPtr)() const = &Cat::meow;

    Cat marshmallow{"Marshmallow"};
    auto name = marshmallow.*dataPtr;
    (marshmallow.*funcPtr)();
}

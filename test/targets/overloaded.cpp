#include <iostream>
#include <string>

void printType(int)
{
    std::cout << "int";
}

void printType(double)
{
    std::cout << "double";
}

void printType(std::string)
{
    std::cout << "string";
}

int main()
{
    printType(0);
    printType(1.4);
    printType("hello");
}

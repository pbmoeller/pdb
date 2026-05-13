#include <iostream>

int libmeowClientCuteness = 100;
bool libmeowClientIsCute();

int main()
{
    std::cout << "Cuteness rating: " << libmeowClientCuteness << "\n";
    std::cout << "Is cute: " << std::boolalpha << libmeowClientIsCute() << "\n";
}
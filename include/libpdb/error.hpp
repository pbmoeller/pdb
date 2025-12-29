#ifndef LIBPDB_ERROR_HPP
#define LIBPDB_ERROR_HPP

#include <cstring>
#include <stdexcept>

namespace pdb {

class Error : public std::runtime_error
{
public:
    [[noreturn]]
    static void send(const std::string& what)
    {
        throw Error(what);
    }
    [[noreturn]]
    static void sendErrno(const std::string& prefix)
    {
        throw Error(prefix + ": " + std::strerror(errno));
    }

private:
    explicit Error(const std::string& what)
        : std::runtime_error(what)
    { }
};
} // namespace pdb

#endif // LIBPDB_ERROR_HPP

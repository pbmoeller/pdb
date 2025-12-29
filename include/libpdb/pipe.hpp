#ifndef LIBPDB_PIPE_HPP
#define LIBPDB_PIPE_HPP

#include <cstddef>
#include <vector>

namespace pdb {

class Pipe
{
    static constexpr int readFd  = 0;
    static constexpr int writeFd = 1;

public:
    explicit Pipe(bool closeOnExec);
    ~Pipe();

    int getRead() const { return m_fds[readFd]; }
    int getWrite() const { return m_fds[writeFd]; };
    int releaseRead();
    int releaseWrite();
    void closeRead();
    void closeWrite();

    std::vector<std::byte> read();
    void write(std::byte* from, size_t bytes);

private:
    int m_fds[2];
};

} // namespace pdb

#endif // LIBPDB_PIPE_HPP

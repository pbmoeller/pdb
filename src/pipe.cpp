#include <libpdb/error.hpp>
#include <libpdb/pipe.hpp>

#include <fcntl.h>
#include <unistd.h>
#include <utility>

namespace pdb {

Pipe::Pipe(bool closeOnExec)
{
    if(pipe2(m_fds, closeOnExec ? O_CLOEXEC : 0) < 0) {
        Error::sendErrno("pipe2 failed");
    }
}

Pipe::~Pipe()
{
    closeRead();
    closeWrite();
}

int Pipe::releaseRead()
{
    return std::exchange(m_fds[readFd], -1);
}

int Pipe::releaseWrite()
{
    return std::exchange(m_fds[writeFd], -1);
}

void Pipe::closeRead()
{
    if(m_fds[readFd] != -1) {
        close(m_fds[readFd]);
        m_fds[readFd] = -1;
    }
}

void Pipe::closeWrite()
{
    if(m_fds[writeFd] != -1) {
        close(m_fds[writeFd]);
        m_fds[writeFd] = -1;
    }
}

std::vector<std::byte> Pipe::read()
{
    char buffer[1024];
    int charsRead;
    if((charsRead = ::read(m_fds[readFd], buffer, sizeof(buffer))) < 0) {
        Error::sendErrno("Pipe read failed");
    }

    auto readBytes = reinterpret_cast<std::byte*>(buffer);
    return std::vector<std::byte>(readBytes, readBytes + charsRead);
}

void Pipe::write(std::byte* from, size_t bytes)
{
    if(::write(m_fds[writeFd], from, bytes) < 0) {
        Error::sendErrno("Pipe write failed");
    }
}

} // namespace pdb

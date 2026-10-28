#include "atm/InputSource.h"

#include <iostream>

#include "crypto/CryptoCore.h"

#if defined(__unix__) || defined(__APPLE__)
#include <sys/select.h>
#include <unistd.h>
#endif

bool InputSource::nextInto(std::string& out)
{
    if (_scripted)
    {
        if (_queue.empty()) return false;
        out.assign(_queue.front());
        CryptoCore::cleanse(_queue.front());
        _queue.pop_front();
        return true;
    }

#if defined(__unix__) || defined(__APPLE__)
    if (std::cin.rdbuf()->in_avail() <= 0)
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        timeval tv{ _timeoutSec, 0 };
        if (select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) <= 0) return false;
    }
#endif

    return static_cast<bool>(std::getline(std::cin, out));
}

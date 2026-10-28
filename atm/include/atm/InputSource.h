#pragma once
#include <cstddef>
#include <deque>
#include <string>

class InputSource
{
private:
    bool _scripted;
    int _timeoutSec;
    std::deque<std::string> _queue;

public:
    explicit InputSource(bool scripted = true, int timeoutSec = 30)
        : _scripted(scripted), _timeoutSec(timeoutSec) {
    }

    void push(std::string line) { _queue.push_back(std::move(line)); }
    bool nextInto(std::string& out);
    std::size_t remaining() const { return _queue.size(); }
};

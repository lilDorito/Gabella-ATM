#pragma once
#include <vector>

#include "audit/ICheckpointSink.h"

class InMemoryCheckpointSink final : public ICheckpointSink
{
private:
    std::vector<Checkpoint> _items;
    bool _fail = false;

public:
    [[nodiscard]] bool submit(const Checkpoint& cp) override
    {
        if (_fail) return false;
        _items.push_back(cp);
        return true;
    }

    void setFail(bool fail) { _fail = fail; }
    const std::vector<Checkpoint>& items() const { return _items; }
};

#pragma once
#include "common/Checkpoint.h"

class ICheckpointSink
{
public:
    virtual ~ICheckpointSink() = default;
    [[nodiscard]] virtual bool submit(const Checkpoint& cp) = 0;
};

#pragma once
#include <optional>

#include "common/Card.h"

class ICardReader
{
public:
    virtual ~ICardReader() = default;

    virtual std::optional<Card> readCard() = 0;
    virtual bool eject() = 0;
    virtual void retain() = 0;
};

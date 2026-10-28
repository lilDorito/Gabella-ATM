#pragma once
#include <string>

#include "atm/ScreenId.h"

class IDisplay
{
public:
    virtual ~IDisplay() = default;

    virtual void show(ScreenId id, const std::string& detail = "") = 0;
};

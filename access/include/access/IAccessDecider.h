#pragma once
#include "common/AccessTypes.h"

class IAccessDecider
{
public:
    virtual ~IAccessDecider() = default;

    [[nodiscard]] virtual Decision decide(const AccessRequest& request) = 0;
};
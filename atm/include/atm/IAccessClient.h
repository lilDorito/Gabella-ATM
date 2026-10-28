#pragma once
#include <string>

#include "common/Action.h"
#include "common/Role.h"

class IAccessClient
{
public:
    virtual ~IAccessClient() = default;

    [[nodiscard]] virtual bool isAllowed(const std::string& staffToken, Action action) = 0;
    virtual bool isVisible(Role role, Action action) const = 0;
};

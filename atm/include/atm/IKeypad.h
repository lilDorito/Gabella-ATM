#pragma once
#include <optional>
#include <string>

#include "common/Action.h"
#include "common/Money.h"

class IKeypad
{
public:
    virtual ~IKeypad() = default;

    virtual bool readHiddenPin(std::string& out) = 0;
    virtual bool readHiddenSecret(std::string& out) = 0;
    virtual std::optional<Action> readAction() = 0;
    virtual std::optional<Money> readAmount() = 0;
    virtual std::optional<std::string> readText() = 0;
    virtual void enable() = 0;
    virtual void disable() = 0;
};

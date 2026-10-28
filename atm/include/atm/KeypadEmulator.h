#pragma once
#include "atm/IKeypad.h"
#include "atm/InputSource.h"

class KeypadEmulator final : public IKeypad
{
private:
    InputSource& _input;
    bool _enabled = true;

public:
    explicit KeypadEmulator(InputSource& input) : _input(input) {}

    bool readHiddenPin(std::string& out) override;
    bool readHiddenSecret(std::string& out) override;
    std::optional<Action> readAction() override;
    std::optional<Money> readAmount() override;
    std::optional<std::string> readText() override;
    void enable() override { _enabled = true; }
    void disable() override { _enabled = false; }
};

#pragma once
#include <functional>

#include "atm/ITamperSensor.h"

class TamperSensorEmulator final : public ITamperSensor
{
private:
    std::function<void()> _handler;

public:
    void onTamper(std::function<void()> handler) override { _handler = std::move(handler); }
    void trigger() override
    {
        if (_handler) _handler();
    }
};

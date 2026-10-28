#pragma once
#include <functional>

class ITamperSensor
{
public:
    virtual ~ITamperSensor() = default;

    virtual void onTamper(std::function<void()> handler) = 0;
    virtual void trigger() = 0;
};

#pragma once
#include <iostream>
#include <string>
#include <vector>

#include "atm/IDisplay.h"

class DisplayEmulator final : public IDisplay
{
private:
    std::ostream& _out;
    std::vector<ScreenId> _history;
    std::vector<std::string> _details;

public:
    explicit DisplayEmulator(std::ostream& out = std::cout) : _out(out) {}

    void show(ScreenId id, const std::string& detail = "") override;

    const std::vector<ScreenId>& history() const { return _history; }
    const std::vector<std::string>& details() const { return _details; }
    bool shown(ScreenId id) const;

    static const char* text(ScreenId id);
};

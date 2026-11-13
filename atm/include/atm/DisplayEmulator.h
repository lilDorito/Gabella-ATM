#pragma once
#include <iostream>
#include <string>
#include <vector>

#include "atm/IDisplay.h"
#include "atm/Terminal.h"

class DisplayEmulator final : public IDisplay
{
private:
    std::ostream& _out;
    term::Style _style;
    std::vector<ScreenId> _history;
    std::vector<std::string> _details;

    void render(ScreenId id, const std::string& detail);
    void renderService(const std::string& detail);

public:
    explicit DisplayEmulator(std::ostream& out = std::cout, term::Style style = {}) : _out(out), _style(style) {}

    void show(ScreenId id, const std::string& detail = "") override;
    const std::vector<ScreenId>& history() const { return _history; }
    const std::vector<std::string>& details() const { return _details; }
    bool shown(ScreenId id) const;
    static const char* text(ScreenId id);
};

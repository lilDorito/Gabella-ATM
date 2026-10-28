#pragma once
#include <cstdint>
#include <map>
#include <string>

#include "atm/IDispenser.h"
#include "crypto/AtmHsm.h"

class DispenserEmulator final : public IDispenser
{
private:
    const std::string _atmId;
    const AtmHsm& _hsm;
    std::map<int, int> _cassettes;
    std::map<int, int> _lastDispensed;
    std::uint64_t _lastSequence = 0;
    bool _locked = false;
    bool _fault = false;

public:
    DispenserEmulator(std::string atmId, const AtmHsm& hsm, std::map<int, int> cassettes);

    [[nodiscard]] DispenseResult dispense(const DispenseCommand& command) override;
    void lock() override { _locked = true; }
    void unlock() override { _locked = false; }
    std::map<int, int> cassetteCounts() const override { return _cassettes; }
    void loadCash(const std::map<int, int>& notes) override;
    std::map<int, int> unloadCash() override;
    std::uint64_t lastSequence() const override { return _lastSequence; }

    void injectHardwareFault(bool on) { _fault = on; }
    const std::map<int, int>& lastDispensed() const { return _lastDispensed; }
};

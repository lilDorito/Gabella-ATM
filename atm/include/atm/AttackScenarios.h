#pragma once
#include <string>

#include "atm/CardReaderEmulator.h"
#include "atm/DispenserEmulator.h"

struct AttackReport
{
    std::string name;
    bool passed;
    std::string details;
};

class ServicePortEmulator
{
private:
    IDispenser& _dispenser;

public:
    explicit ServicePortEmulator(IDispenser& dispenser) : _dispenser(dispenser) {}

    DispenseResult sendRawDispense(const std::string& atmId, std::int64_t amountKop);
};

class AttackScenarios
{
private:
    DispenserEmulator& _dispenser;
    CardReaderEmulator& _reader;
    std::string _atmId;

public:
    AttackScenarios(DispenserEmulator& dispenser, CardReaderEmulator& reader, std::string atmId)
        : _dispenser(dispenser), _reader(reader), _atmId(std::move(atmId)) {
    }

    AttackReport runJackpotting();
    AttackReport runSkimmer();
    AttackReport runStepSkipping();
};

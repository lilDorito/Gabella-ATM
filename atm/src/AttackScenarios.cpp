#include "atm/AttackScenarios.h"

#include "atm/SessionStateMachine.h"

DispenseResult ServicePortEmulator::sendRawDispense(const std::string& atmId, std::int64_t amountKop)
{
    DispenseCommand command;
    command.atmId = atmId;
    command.sessionId = "attacker";
    command.amountKop = amountKop;
    command.sequence = 1000000;
    return _dispenser.dispense(command);
}

AttackReport AttackScenarios::runJackpotting()
{
    const auto before = _dispenser.cassetteCounts();
    ServicePortEmulator port(_dispenser);
    const DispenseResult r = port.sendRawDispense(_atmId, 5000LL * 100);
    const bool ok = r == DispenseResult::InvalidSignature && _dispenser.cassetteCounts() == before;
    return { "Jackpotting via service port", ok, std::string("result=") + dispenseResultToString(r) };
}

AttackReport AttackScenarios::runSkimmer()
{
    _reader.attachSkimmer();
    _reader.insertCard("4111111111111111", 12, 2030);
    const std::size_t before = _reader.skimmed().size();
    (void)_reader.readCard();
    (void)_reader.eject();
    const bool ok = _reader.skimmed().size() == before + 1;
    return { "Card reader skimmer", ok, "captured=pan,expiry pin_captured=false" };
}

AttackReport AttackScenarios::runStepSkipping()
{
    Session session("attack", Card("4111111111111111", 12, 2030));
    SessionStateMachine::transition(session, SessionState::CardInserted);
    SessionStateMachine::transition(session, SessionState::OperationSelect);
    SessionStateMachine::transition(session, SessionState::AwaitingPin);

    bool blocked = false;
    try
    {
        SessionStateMachine::transition(session, SessionState::Dispensing);
    }
    catch (const IllegalTransitionError&)
    {
        blocked = true;
    }

    const bool ok = blocked && session.getState() == SessionState::AwaitingPin;
    return { "Step skipping (PIN -> dispense)", ok, "result=IllegalTransitionError state=AwaitingPin" };
}

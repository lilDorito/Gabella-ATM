#include "atm/AttackScenarios.h"

#include <algorithm>
#include <vector>

#include "atm/SessionStateMachine.h"
#include "audit/LogFormat.h"

namespace
{
bool editEntry(std::vector<std::string>& lines, std::size_t index)
{
    auto entry = parseEntry(lines[index]);
    if (!entry) return false;

    LogEvent event = entry->getEvent();
    event.details = "tampered";
    lines[index] = formatEntryLine(LogEntry(entry->getSeqNo(), entry->getTimestamp(), event, entry->getPrevHash(), entry->getHash()));
    return true;
}

bool rewriteChain(std::vector<std::string>& lines, std::size_t tamperedIndex)
{
    std::string previous = genesisHash();
    for (std::size_t i = 0; i < lines.size(); ++i)
    {
        auto entry = parseEntry(lines[i]);
        if (!entry) return false;

        LogEvent event = entry->getEvent();
        if (i == tamperedIndex) event.details = "tampered";

        const std::string hash = computeEntryHash(previous, serializeEntry(entry->getSeqNo(), entry->getTimestamp(), event));
        lines[i] = formatEntryLine(LogEntry(entry->getSeqNo(), entry->getTimestamp(), event, previous, hash));
        previous = hash;
    }
    return true;
}
}

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

AttackReport AttackScenarios::runReplay(IServerLink& link, const AuthRequest& captured)
{
    const auto response = link.authorize(captured);
    const bool refused = !response || (response->status != AuthStatus::Approved && !response->command);
    const std::string status = response ? std::string("status=") + authStatusToString(response->status) : std::string("status=no_response");
    return { "Replay of a captured authorization request", refused, status };
}

AttackReport AttackScenarios::runLogTampering(InMemoryLogStorage& storage, const LogVerifier& verifier, const std::optional<Checkpoint>& checkpoint)
{
    const std::vector<std::string> original = storage.lines();
    if (original.size() < 3 || !verifier.verifyChain().ok) return { "Audit log tampering", false, "result=precondition_failed" };

    storage.lines() = original;
    const bool edited = editEntry(storage.lines(), 1);
    const bool editDetected = edited && !verifier.verifyChain().ok;

    storage.lines() = original;
    storage.lines().erase(storage.lines().begin() + 1);
    const bool deleteDetected = !verifier.verifyChain().ok;

    bool truncateDetected = true;
    bool rewriteDetected = true;
    if (checkpoint)
    {
        storage.lines() = original;
        const std::size_t keep = checkpoint->seqNo > 1 ? static_cast<std::size_t>(checkpoint->seqNo - 1) : 0;
        if (keep < storage.lines().size()) storage.lines().resize(keep);
        truncateDetected = !verifier.verifyAgainstCheckpoint(*checkpoint).ok;

        storage.lines() = original;
        const bool rewritten = rewriteChain(storage.lines(), 1);
        rewriteDetected = rewritten && verifier.verifyChain().ok && !verifier.verifyAgainstCheckpoint(*checkpoint).ok;
    }

    storage.lines() = original;
    const bool restored = verifier.verifyChain().ok;

    const bool ok = editDetected && deleteDetected && truncateDetected && rewriteDetected && restored;
    const std::string anchored = checkpoint ? "detected" : "skipped";
    return { "Audit log tampering", ok,
        std::string("edit=") + (editDetected ? "detected" : "missed") + " delete=" + (deleteDetected ? "detected" : "missed")
            + " truncate=" + (checkpoint ? (truncateDetected ? "detected" : "missed") : "skipped") + " rewrite=" + (checkpoint ? (rewriteDetected ? "detected" : "missed") : "skipped")
            + " restored=" + (restored ? "yes" : "no") + " anchored=" + anchored };
}

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "Check.h"
#include "HsmFixture.h"
#include "FakeAccessClient.h"
#include "FakeBank.h"
#include "FakeServerLink.h"

#include "atm/AtmController.h"
#include "atm/AttackScenarios.h"
#include "atm/CardReaderEmulator.h"
#include "atm/CounterStore.h"
#include "atm/DispenserEmulator.h"
#include "atm/DisplayEmulator.h"
#include "atm/InputSource.h"
#include "atm/KeypadEmulator.h"
#include "atm/SessionStateMachine.h"
#include "atm/TamperSensorEmulator.h"
#include "audit/AnchorStore.h"
#include "audit/AuditLogger.h"
#include "audit/CheckpointPayload.h"
#include "audit/HsmAuditSigners.h"
#include "audit/InMemoryCheckpointSink.h"
#include "audit/LogFormat.h"
#include "audit/LogStorage.h"
#include "audit/LogVerifier.h"
#include "common/Clock.h"
#include "common/Invariant.h"

using gabella_test::check;
using gabella_test::section;

namespace
{
const std::string kAtmId = "ATM-001";
const std::string kPan = "4111111111111111";
const std::string kPin = "4821";
const std::string kPassword = "S3cretPass";

long cashTotal(const std::map<int, int>& notes)
{
    long total = 0;
    for (const auto& [value, count] : notes) total += static_cast<long>(value) * count;
    return total;
}

struct Rig
{
    HsmFixture fx;
    FakeClock clock{ 1792000000 };
    InputSource input{ true };
    std::ostringstream screen;
    CardReaderEmulator reader;
    KeypadEmulator keypad{ input };
    DisplayEmulator display{ screen };
    InMemoryCounterStore dispenseSeq;
    InMemoryCounterStore commandSeq;
    DispenserEmulator dispenser{ kAtmId, *fx.atm, clock, dispenseSeq, { { 100, 50 }, { 200, 50 }, { 500, 50 }, { 1000, 50 } } };
    TamperSensorEmulator tamper;
    PinModule pin{ *fx.atm };
    InMemoryLogStorage storage;
    InMemoryAnchorStore anchors;
    InMemoryCheckpointSink checkpoints;
    AtmHsmAuditSigner signer{ *fx.atm };
    AuditLogger logger{ kAtmId, storage, anchors, signer, checkpoints, clock };
    LogVerifier verifier{ storage, signer };
    FakeBank bank{ *fx.bank, clock, kPan, kPin };
    FakeAccessClient access{ bank };
    FakeServerLink link{ bank, *fx.atm };
    AtmController atm{ kAtmId, reader, keypad, display, dispenser, tamper, pin, *fx.atm, logger, verifier, access, link, commandSeq, clock };

    Rig() { logger.init(); }

    void insert(int month = 12, int year = 2030, const std::string& pan = kPan) { reader.insertCard(pan, month, year); }

    void type(std::initializer_list<const char*> lines)
    {
        for (const char* line : lines) input.push(line);
    }

    std::vector<LogEvent> events() const
    {
        std::vector<LogEvent> out;
        for (const std::string& line : storage.readAll())
        {
            auto entry = parseEntry(line);
            if (entry) out.push_back(entry->getEvent());
        }
        return out;
    }

    bool has(EventType type) const
    {
        for (const LogEvent& e : events())
        {
            if (e.type == type) return true;
        }
        return false;
    }

    std::size_t indexOf(EventType type) const
    {
        std::size_t i = 0;
        for (const LogEvent& e : events())
        {
            if (e.type == type) return i;
            ++i;
        }
        return static_cast<std::size_t>(-1);
    }

    bool detailShown(const std::string& needle) const
    {
        for (const std::string& d : display.details())
        {
            if (d.find(needle) != std::string::npos) return true;
        }
        return false;
    }

    long cash() const { return cashTotal(dispenser.cassetteCounts()); }
};

void stateMachineTests()
{
    section("SessionStateMachine");
    using S = SessionState;

    Session s("t", Card(kPan, 12, 2030));
    const S path[] = { S::CardInserted, S::OperationSelect, S::AwaitingPin, S::Authorizing, S::Approved, S::Dispensing, S::Completing, S::Idle };
    bool ok = true;
    for (S to : path)
    {
        SessionStateMachine::transition(s, to);
        ok = ok && s.getState() == to;
    }
    check(ok, "every allowed transition succeeds");

    SessionStateMachine::transition(s, S::CardInserted);
    SessionStateMachine::transition(s, S::OperationSelect);
    SessionStateMachine::transition(s, S::AwaitingPin);
    bool threw = false;
    try
    {
        SessionStateMachine::transition(s, S::Dispensing);
    }
    catch (const IllegalTransitionError&)
    {
        threw = true;
    }
    check(threw && s.getState() == S::AwaitingPin, "AwaitingPin -> Dispensing throws, state unchanged");

    check(!SessionStateMachine::isAllowedTransition(S::Terminated, S::Terminated), "Terminated -> Terminated is rejected");
    check(!SessionStateMachine::isAllowedTransition(S::Idle, S::Terminated), "Idle -> Terminated is rejected");
    check(SessionStateMachine::isAllowedTransition(S::Idle, S::OutOfService) && SessionStateMachine::isAllowedTransition(S::Dispensing, S::OutOfService), "tamper reaches OutOfService from any state");
    check(!SessionStateMachine::isAllowedTransition(S::OutOfService, S::Dispensing), "OutOfService cannot jump to Dispensing");
    check(SessionStateMachine::isAllowedTransition(S::OutOfService, S::Idle), "OutOfService -> Idle is the recovery path");

    Session w("w", Card(kPan, 12, 2030));
    SessionStateMachine::transition(w, S::CardInserted);
    SessionStateMachine::transition(w, S::OperationSelect);
    w.setAction(Action::Withdraw);
    check(!SessionStateMachine::canDispense(w), "canDispense is false before Approved");
    SessionStateMachine::transition(w, S::AwaitingPin);
    SessionStateMachine::transition(w, S::Authorizing);
    SessionStateMachine::transition(w, S::Approved);
    check(SessionStateMachine::canDispense(w), "canDispense is true in Approved for Withdraw");
    w.setAction(Action::CheckBalance);
    check(!SessionStateMachine::canDispense(w), "canDispense is false for CheckBalance");
}

void dispenserTests()
{
    section("DispenserEmulator (real Ed25519 signatures)");

    Rig r;
    DispenseCommand forged = r.bank.signDispense(kAtmId, 50000, 1);
    forged.signature[0] = static_cast<char>(forged.signature[0] ^ 1);
    check(r.dispenser.dispense(forged) == DispenseResult::InvalidSignature, "forged signature is rejected");
    check(r.dispenser.lastSequence() == 0, "forged command does not burn the sequence number");

    check(r.dispenser.dispense(r.bank.signDispense(kAtmId, 50000, 1)) == DispenseResult::Ok, "valid command is executed");
    check(r.dispenser.lastDispensed().count(500) == 1 && r.dispenser.lastDispensed().at(500) == 1, "500 UAH is paid with one 500 note");
    check(r.dispenser.dispense(r.bank.signDispense(kAtmId, 50000, 1)) == DispenseResult::ReplayedSequence, "same sequence is a replay");
    check(r.dispenser.dispense(r.bank.signDispense(kAtmId, 50000, 0)) == DispenseResult::ReplayedSequence, "lower sequence is a replay");
    check(r.dispenser.dispense(r.bank.signDispense("ATM-999", 50000, 2)) == DispenseResult::WrongAtm, "command for another ATM is rejected");
    check(r.dispenser.dispense(r.bank.signDispense(kAtmId, 55000, 3)) == DispenseResult::AmountNotDispensable, "550 UAH cannot be composed");
    check(r.dispenser.dispense(r.bank.signDispense(kAtmId, 0, 3)) == DispenseResult::AmountNotDispensable, "zero amount is rejected");
    check(r.dispenser.lastSequence() == 1, "rejected commands leave the sequence untouched");

    Rig few;
    (void)few.dispenser.unloadCash();
    few.dispenser.loadCash({ { 500, 1 }, { 200, 3 } });
    check(few.dispenser.dispense(few.bank.signDispense(kAtmId, 60000, 1)) == DispenseResult::Ok && few.dispenser.lastDispensed().at(200) == 3, "600 UAH from 1x500 + 3x200 needs search, not greedy");
    check(few.dispenser.dispense(few.bank.signDispense(kAtmId, 500000, 2)) == DispenseResult::InsufficientCash, "not enough notes");

    Rig locked;
    locked.dispenser.lock();
    check(locked.dispenser.dispense(locked.bank.signDispense(kAtmId, 10000, 1)) == DispenseResult::Locked, "locked dispenser rejects a valid command");
    locked.dispenser.unlock();
    check(locked.dispenser.dispense(locked.bank.signDispense(kAtmId, 10000, 1)) == DispenseResult::Ok, "unlock restores operation");

    Rig fault;
    fault.dispenser.injectHardwareFault(true);
    const DispenseResult faulted = fault.dispenser.dispense(fault.bank.signDispense(kAtmId, 50000, 1));
    check(faulted == DispenseResult::HardwareFault && fault.cash() == 90000 && fault.dispenser.lastSequence() == 1, "hardware fault keeps cassettes intact and burns the sequence");

    Rig domain;
    DispenseCommand c;
    c.atmId = kAtmId;
    c.sessionId = "s";
    c.amountKop = 50000;
    c.sequence = 1;
    c.signature = *domain.fx.bank->sign(SignDomain::Response, c.signedPayload());
    check(domain.dispenser.dispense(c) == DispenseResult::InvalidSignature, "signature from another domain is rejected");

    bool threw = false;
    try
    {
        DispenserEmulator bad("", *domain.fx.atm, domain.clock, domain.dispenseSeq, {});
    }
    catch (const InvariantViolation&)
    {
        threw = true;
    }
    check(threw, "dispenser refuses an empty atmId");
}

void lifetimeAndRestartTests()
{
    section("Command lifetime and restart");

    Rig late;
    const DispenseCommand held = late.bank.signDispense(kAtmId, 50000, 1);
    late.clock.advance(kDispenseCommandLifetimeSeconds + 1);
    check(late.dispenser.dispense(held) == DispenseResult::Expired && late.cash() == 90000, "a command held back past its lifetime is refused");
    check(late.dispenser.lastSequence() == 0, "an expired command does not burn the sequence number");
    DispenseCommand stretched = held;
    stretched.expiresAt += 3600;
    check(late.dispenser.dispense(stretched) == DispenseResult::InvalidSignature, "extending the expiry breaks the signature");
    check(kDispenseCommandLifetimeSeconds < 120, "commands expire before the server may mark a withdrawal UNCERTAIN");

    Rig boot;
    const DispenseCommand paid = boot.bank.signDispense(kAtmId, 50000, 1);
    check(boot.dispenser.dispense(paid) == DispenseResult::Ok, "command executed before restart");
    DispenserEmulator rebooted{ kAtmId, *boot.fx.atm, boot.clock, boot.dispenseSeq, { { 500, 10 } } };
    check(rebooted.lastSequence() == 1, "dispenser sequence survives a restart");
    check(rebooted.dispense(paid) == DispenseResult::ReplayedSequence, "an executed command is rejected after restart");
    check(rebooted.dispense(boot.bank.signDispense(kAtmId, 50000, 2)) == DispenseResult::Ok, "the next command still works after restart");

    Rig fullDisk;
    fullDisk.dispenseSeq.setFailSaves(true);
    const DispenseResult unsaved = fullDisk.dispenser.dispense(fullDisk.bank.signDispense(kAtmId, 50000, 1));
    check(unsaved == DispenseResult::HardwareFault && fullDisk.cash() == 90000 && fullDisk.dispenser.lastSequence() == 0, "no payout when the sequence cannot be stored");

    Rig blind;
    blind.dispenseSeq.setUnreadable(true);
    DispenserEmulator unsure{ kAtmId, *blind.fx.atm, blind.clock, blind.dispenseSeq, { { 500, 10 } } };
    check(unsure.dispense(blind.bank.signDispense(kAtmId, 50000, 1)) == DispenseResult::HardwareFault, "dispenser with an unreadable counter refuses every command");

    Rig keys;
    auto first = keys.fx.bank->prepareWorkingKey(KeyType::Mac);
    const SignedCommand oldKey = keys.bank.signCommand(1, Action::UpdateWorkingKey, kAtmId, "Mac|" + *first);
    keys.link.queuedCommands.push_back(oldKey);
    keys.atm.processServerCommands();
    check(keys.fx.bank->commitWorkingKey(KeyType::Mac), "first MAC key installed");
    auto second = keys.fx.bank->prepareWorkingKey(KeyType::Mac);
    keys.link.queuedCommands.push_back(keys.bank.signCommand(2, Action::UpdateWorkingKey, kAtmId, "Mac|" + *second));
    keys.atm.processServerCommands();
    check(keys.fx.bank->commitWorkingKey(KeyType::Mac), "second MAC key installed");
    const auto macBefore = keys.fx.atm->macMessage("probe");
    {
        AtmController restarted{ kAtmId, keys.reader, keys.keypad, keys.display, keys.dispenser, keys.tamper, keys.pin, *keys.fx.atm, keys.logger, keys.verifier, keys.access, keys.link,
            keys.commandSeq, keys.clock };
        keys.link.queuedCommands.push_back(oldKey);
        restarted.processServerCommands();
    }
    check(keys.link.commandResults.size() == 2 && keys.fx.atm->macMessage("probe") == macBefore, "an old key update is not replayed after restart");

    const std::filesystem::path dir = std::filesystem::temp_directory_path() / "gabella-counter-test";
    std::filesystem::remove_all(dir);
    {
        FileCounterStore fresh(dir / "dispense.seq");
        check(fresh.load() == std::optional<std::uint64_t>(0), "a missing counter file reads as a fresh device");
        check(fresh.save(41) && fresh.save(42), "counter file saves");
        FileCounterStore reopened(dir / "dispense.seq");
        check(reopened.load() == std::optional<std::uint64_t>(42), "counter file survives reopening");

        std::ofstream(dir / "broken.seq") << "42x\n";
        check(!FileCounterStore(dir / "broken.seq").load().has_value(), "a corrupt counter file is unreadable, not zero");

        Rig onDisk;
        FileCounterStore sequence(dir / "atm.seq");
        DispenserEmulator before{ kAtmId, *onDisk.fx.atm, onDisk.clock, sequence, { { 500, 10 } } };
        const DispenseCommand once = onDisk.bank.signDispense(kAtmId, 50000, 7);
        check(before.dispense(once) == DispenseResult::Ok, "dispenser with a file counter pays once");
        FileCounterStore sequenceAfterReboot(dir / "atm.seq");
        DispenserEmulator after{ kAtmId, *onDisk.fx.atm, onDisk.clock, sequenceAfterReboot, { { 500, 10 } } };
        check(after.dispense(once) == DispenseResult::ReplayedSequence, "the same command is refused after a restart from disk");
    }
    std::filesystem::remove_all(dir);

    Rig stuck;
    stuck.commandSeq.setFailSaves(true);
    auto blob = stuck.fx.bank->prepareWorkingKey(KeyType::Mac);
    const auto stuckBefore = stuck.fx.atm->macMessage("probe");
    stuck.link.queuedCommands.push_back(stuck.bank.signCommand(1, Action::UpdateWorkingKey, kAtmId, "Mac|" + *blob));
    stuck.atm.processServerCommands();
    const bool refused = stuck.link.commandResults.size() == 1 && !stuck.link.commandResults[0].second;
    check(refused && stuck.fx.atm->macMessage("probe") == stuckBefore, "a command is not executed when its sequence cannot be stored");
}

void attackTests()
{
    section("Hardware attack scenarios");

    Rig r;
    AttackScenarios attacks(r.dispenser, r.reader, kAtmId);
    const AttackReport jackpot = attacks.runJackpotting();
    const AttackReport skimmer = attacks.runSkimmer();
    const AttackReport skip = attacks.runStepSkipping();
    check(jackpot.passed, "jackpotting through the service port: " + jackpot.details);
    check(skimmer.passed, "skimmer sees only number and expiry");
    check(skip.passed, "step skipping is blocked");
    check(r.reader.skimmed().size() == 1 && r.reader.skimmed()[0].pan == kPan && r.reader.skimmed()[0].expYear == 2030, "skimmed data holds nothing but pan and expiry");
}

void reuseAttackTests()
{
    section("Moving captured ciphertexts into new requests");

    Rig pinRig;
    pinRig.insert();
    pinRig.type({ "2", "500", kPin.c_str() });
    pinRig.atm.runSession();
    const AuthRequest captured = pinRig.bank.seen.back();
    const std::int64_t balanceAfterFirst = pinRig.bank.balanceKop;

    const std::string nonce = "replanted-nonce1";
    const std::int64_t now = pinRig.clock.nowUnix();
    const AuthRequest draft(captured.getAtmId(), captured.getSessionId(), Action::Withdraw, captured.getCiphertext(), nonce, now, captured.getPan(), 500000, "");
    const auto mac = pinRig.fx.atm->macMessage(draft.macPayload());
    const AuthRequest forged(captured.getAtmId(), captured.getSessionId(), Action::Withdraw, captured.getCiphertext(), nonce, now, captured.getPan(), 500000, *mac);
    const AuthResponse answer = pinRig.bank.authorize(forged);
    check(answer.status != AuthStatus::Approved && !answer.command && pinRig.bank.balanceKop == balanceAfterFirst, "A17: old PIN ciphertext with a new nonce, amount and valid MAC is refused");

    Rig staff;
    staff.type({ "E-01", kPassword.c_str(), "0" });
    staff.atm.runServiceMenu();
    check(staff.link.loginRequests.size() == 1 && staff.link.loggedOut.size() == 1, "engineer signs in once");
    const StaffLoginRequest login = staff.link.loginRequests.back();
    check(!staff.bank.staffLogin(login).has_value(), "an exact replay of a login request is refused (nonce already used)");

    StaffLoginRequest moved = login;
    moved.nonce = "fresh-login-nonce";
    moved.timestamp = staff.clock.nowUnix();
    check(!staff.bank.staffLogin(moved).has_value(), "A18: old sealed password in a new login request is refused");

    StaffLoginRequest stale = login;
    stale.nonce = "stale-login-nonce";
    staff.clock.advance(120);
    check(!staff.bank.staffLogin(stale).has_value(), "a login request outside the time window is refused");
}

void withdrawalTests()
{
    section("Withdrawal end to end");

    Rig r;
    r.insert();
    r.type({ "2", "500", kPin.c_str() });
    r.atm.runSession();

    check(r.bank.balanceKop == 1234000 - 50000, "server balance decreased by 500 UAH");
    check(r.cash() == 90000 - 500, "cassettes decreased by 500 UAH");
    check(r.display.shown(ScreenId::TakeCash), "TakeCash screen shown");
    check(r.reader.status() == CardReaderEmulator::Status::Ejected, "card returned");
    check(r.atm.currentState() == SessionState::Idle, "back in Idle");
    check(r.link.reports.size() == 1 && r.link.reports[0].result == DispenseResult::Ok && cashTotal(r.link.reports[0].cassetteCounts) == 90000 - 500, "dispense report carries cassette counters");
    check(r.link.endedSessions.size() == 1, "session closed on the server");
    check(r.bank.seen.size() == 1 && r.bank.seen[0].getAmount() == 50000 && r.bank.seen[0].getPan() == kPan, "server received the real AuthRequest from PinModule");
    check(r.bank.seen[0].getCiphertext().find(kPin) == std::string::npos, "PIN is not visible in the request");
    check(r.has(EventType::DISPENSE_REQUESTED) && r.has(EventType::DISPENSE_COMPLETED), "write-ahead and completion events are logged");
    check(r.indexOf(EventType::DISPENSE_REQUESTED) < r.indexOf(EventType::DISPENSE_COMPLETED), "DISPENSE_REQUESTED precedes DISPENSE_COMPLETED");
    check(r.verifier.verifyChain().ok, "ATM log chain verifies");
    check(!r.checkpoints.items().empty() && r.verifier.verifyAgainstCheckpoint(r.checkpoints.items().back()).ok, "checkpoint sealed at the end of the session verifies");
    check(r.screen.str().find(kPan) == std::string::npos, "card number never reaches the screen");

    bool leak = false;
    for (const LogEvent& e : r.events())
    {
        if (e.details.find(kPin) != std::string::npos || e.details.find(kPan) != std::string::npos || e.actorId.find(kPin) != std::string::npos || e.maskedPan == kPan) leak = true;
    }
    check(!leak, "no PIN or full card number in the log");

    Rig b;
    b.insert();
    b.type({ "1", "1111", kPin.c_str() });
    b.atm.runSession();
    check(b.detailShown("12340.00"), "balance shown after a wrong PIN and a correct one");
    check(b.display.shown(ScreenId::WrongPin), "WrongPin screen shown");
    check(b.cash() == 90000 && b.link.reports.empty(), "balance check dispenses nothing");

    Rig blocked;
    blocked.insert();
    blocked.type({ "2", "500", "1111", "2222", "3333" });
    blocked.atm.runSession();
    check(blocked.display.shown(ScreenId::CardBlocked) && blocked.reader.status() == CardReaderEmulator::Status::Retained, "three wrong PINs retain the card");
    check(blocked.has(EventType::CARD_RETAINED) && blocked.atm.currentState() == SessionState::Idle, "retention is logged and ATM is Idle again");

    Rig poor;
    poor.bank.balanceKop = 10000;
    poor.insert();
    poor.type({ "2", "500", kPin.c_str() });
    poor.atm.runSession();
    check(poor.display.shown(ScreenId::InsufficientFunds) && poor.cash() == 90000, "insufficient funds dispenses nothing");

    Rig big;
    big.insert();
    big.type({ "2", "20000" });
    big.atm.runSession();
    check(big.display.shown(ScreenId::LimitExceeded) && big.bank.seen.empty(), "amount over 10000 is stopped on the ATM without asking the server");

    Rig odd;
    odd.insert();
    odd.type({ "2", "550" });
    odd.atm.runSession();
    check(odd.display.shown(ScreenId::Error) && odd.bank.seen.empty(), "amount not multiple of 100 is rejected");
}

void cardAndInputTests()
{
    section("Card checks and timeouts");

    Rig expired;
    expired.insert(9, 2026);
    expired.type({ "1" });
    expired.atm.runSession();
    check(expired.has(EventType::CARD_REJECTED) && expired.bank.seen.empty() && expired.reader.status() == CardReaderEmulator::Status::Ejected, "expired card is rejected locally");

    Rig luhn;
    luhn.insert(12, 2030, "4111111111111112");
    luhn.atm.runSession();
    check(luhn.has(EventType::CARD_REJECTED), "Luhn failure is rejected locally");

    Rig idle;
    idle.insert();
    idle.atm.runSession();
    check(idle.display.shown(ScreenId::TakeCard) && idle.atm.currentState() == SessionState::Idle, "no operation chosen ends the session");

    Rig cancel;
    cancel.insert();
    cancel.type({ "1", "C" });
    cancel.atm.runSession();
    check(cancel.bank.seen.empty() && cancel.reader.status() == CardReaderEmulator::Status::Ejected, "cancelled PIN entry never reaches the server");

    Rig left;
    left.reader.setCardTakenOnEject(false);
    left.insert();
    left.type({ "1", kPin.c_str() });
    left.atm.runSession();
    check(left.reader.status() == CardReaderEmulator::Status::Retained && left.has(EventType::CARD_RETAINED), "card left in the slot is retained");

    Rig next;
    next.insert();
    next.type({ "1", kPin.c_str() });
    next.atm.runSession();
    next.insert();
    next.type({ "1", kPin.c_str() });
    next.atm.runSession();
    check(next.link.endedSessions.size() == 2, "two consecutive sessions complete independently");
}

void serverFailureTests()
{
    section("Fail-closed behaviour");

    Rig down;
    down.link.online = false;
    down.insert();
    down.type({ "2", "500", kPin.c_str() });
    down.atm.runSession();
    check(down.display.shown(ScreenId::Error) && down.cash() == 90000 && down.reader.status() == CardReaderEmulator::Status::Ejected, "server down: nothing dispensed, card returned");

    Rig forged;
    forged.link.alterInTransit = [](AuthResponse& r)
    {
        r.status = AuthStatus::Approved;
        r.balance = Money::fromKop(1);
    };
    forged.insert();
    forged.type({ "1", "0000" });
    forged.atm.runSession();
    check(forged.display.shown(ScreenId::Error) && !forged.display.shown(ScreenId::ShowBalance), "response with a broken signature is treated as a refusal");

    Rig foreign;
    foreign.link.alterInTransit = [](AuthResponse& r) { r.sessionId = "other"; };
    foreign.insert();
    foreign.type({ "2", "500", kPin.c_str() });
    foreign.atm.runSession();
    check(foreign.display.shown(ScreenId::Error) && foreign.cash() == 90000, "response for another session is refused");

    Rig mismatch;
    mismatch.bank.commandAmountOverrideKop = 500000;
    mismatch.insert();
    mismatch.type({ "2", "500", kPin.c_str() });
    mismatch.atm.runSession();
    check(mismatch.cash() == 90000 && mismatch.display.shown(ScreenId::Error), "validly signed command for another amount is refused");

    Rig logFail;
    logFail.link.beforeReply = [&logFail] { logFail.storage.setFailAppends(true); };
    logFail.insert();
    logFail.type({ "2", "500", kPin.c_str() });
    logFail.atm.runSession();
    check(logFail.cash() == 90000 && logFail.atm.currentState() == SessionState::OutOfService, "write-ahead failure: no cash and ATM goes OutOfService");
    check(logFail.reader.status() == CardReaderEmulator::Status::Ejected, "card is returned to the customer");

    logFail.insert();
    logFail.atm.runSession();
    check(logFail.display.history().back() == ScreenId::OutOfService && logFail.reader.status() == CardReaderEmulator::Status::Ejected, "OutOfService ATM does not start a session");

    logFail.link.queuedCommands.push_back(logFail.bank.signCommand(1, Action::RestoreFromOutOfService, kAtmId));
    logFail.atm.processServerCommands();
    const bool restored = logFail.atm.currentState() == SessionState::Idle && logFail.link.commandResults.size() == 1 && logFail.link.commandResults[0].second;
    check(restored, "signed RestoreFromOutOfService returns the ATM to Idle");
}

void tamperTests()
{
    section("Tamper");

    Rig r;
    r.link.beforeReply = [&r] { r.tamper.trigger(); };
    r.insert();
    r.type({ "2", "500", kPin.c_str() });
    r.atm.runSession();
    check(r.atm.currentState() == SessionState::OutOfService && r.fx.atm->isDestroyed(), "tamper mid-authorization: OutOfService and HSM wiped");
    check(r.cash() == 90000, "no cash after tamper even though the server approved");
    check(r.link.tamperReported && r.has(EventType::TAMPER_DETECTED), "tamper reported and logged");
    check(r.reader.status() == CardReaderEmulator::Status::Retained, "card retained on tamper");
    check(r.link.endedSessions.size() == 1, "the client session is closed on the server even when the card is retained");
    check(r.dispenser.dispense(r.bank.signDispense(kAtmId, 10000, 99)) == DispenseResult::Locked, "dispenser is locked");

    r.link.queuedCommands.push_back(r.bank.signCommand(1, Action::RestoreFromOutOfService, kAtmId));
    r.atm.processServerCommands();
    check(r.atm.currentState() == SessionState::OutOfService && r.link.commandResults.size() == 1 && !r.link.commandResults[0].second, "restore without new key ceremony is refused");

    check(r.fx.atm->installMasterKey(HsmFixture::kMasterKey), "on-site ceremony installs a fresh master key");
    std::uint64_t seq = 1;
    for (const auto& [type, name] : { std::pair{ KeyType::Encryption, "Encryption" }, std::pair{ KeyType::Mac, "Mac" }, std::pair{ KeyType::Audit, "Audit" } })
    {
        auto blob = r.fx.bank->prepareWorkingKey(type);
        r.link.queuedCommands.push_back(r.bank.signCommand(++seq, Action::UpdateWorkingKey, kAtmId, std::string(name) + "|" + *blob));
        r.atm.processServerCommands();
        check(r.link.commandResults.back().second && r.fx.bank->commitWorkingKey(type), std::string("signed ") + name + " key is installed during recovery");
    }
    check(r.atm.currentState() == SessionState::OutOfService, "new keys alone do not return the ATM to service");

    r.link.queuedCommands.push_back(r.bank.signCommand(++seq, Action::RestoreFromOutOfService, kAtmId));
    r.atm.processServerCommands();
    check(r.atm.currentState() == SessionState::Idle && r.link.commandResults.back().second, "signed restore after the key ceremony returns the ATM to service");

    r.link.beforeReply = nullptr;
    r.insert();
    r.type({ "2", "500", kPin.c_str() });
    r.atm.runSession();
    check(r.cash() == 89500 && r.display.shown(ScreenId::TakeCash), "a withdrawal works again after recovery");

    Rig idle;
    idle.tamper.trigger();
    check(idle.atm.currentState() == SessionState::OutOfService, "tamper while idle");
    idle.insert();
    idle.atm.runSession();
    check(idle.display.history().back() == ScreenId::OutOfService, "no card accepted after tamper");
}

void commandTests()
{
    section("Signed server commands");

    Rig r;
    SignedCommand forged = r.bank.signCommand(1, Action::RestoreFromOutOfService, kAtmId);
    forged.signature[0] = static_cast<char>(forged.signature[0] ^ 1);
    r.link.queuedCommands.push_back(forged);
    r.atm.processServerCommands();
    check(r.link.commandResults.empty() && r.has(EventType::ACCESS_DENIED), "forged command is ignored and logged");

    r.link.queuedCommands.push_back(r.bank.signCommand(1, Action::RestoreFromOutOfService, kAtmId));
    r.atm.processServerCommands();
    check(r.link.commandResults.size() == 1, "forged command did not burn the sequence number");

    r.link.queuedCommands.push_back(r.bank.signCommand(1, Action::RestoreFromOutOfService, kAtmId));
    r.atm.processServerCommands();
    check(r.link.commandResults.size() == 1, "replayed command is ignored");

    r.link.queuedCommands.push_back(r.bank.signCommand(2, Action::RestoreFromOutOfService, "ATM-999"));
    r.atm.processServerCommands();
    check(r.link.commandResults.size() == 1, "command for another ATM is ignored");

    auto blob = r.fx.bank->prepareWorkingKey(KeyType::Mac);
    check(blob.has_value(), "bank prepares a new MAC key");
    r.link.queuedCommands.push_back(r.bank.signCommand(3, Action::UpdateWorkingKey, kAtmId, "Mac|" + *blob));
    r.atm.processServerCommands();
    check(r.link.commandResults.size() == 2 && r.link.commandResults[1].second && r.has(EventType::KEY_UPDATED), "UpdateWorkingKey is applied");
    check(r.fx.bank->commitWorkingKey(KeyType::Mac), "bank switches to the new MAC key");

    r.insert();
    r.type({ "1", kPin.c_str() });
    r.atm.runSession();
    check(r.detailShown("12340.00"), "requests authenticate with the rotated MAC key");

    auto auditBlob = r.fx.bank->prepareWorkingKey(KeyType::Audit);
    r.link.queuedCommands.push_back(r.bank.signCommand(4, Action::UpdateWorkingKey, kAtmId, "Audit|" + *auditBlob));
    r.atm.processServerCommands();
    check(r.fx.bank->commitWorkingKey(KeyType::Audit), "bank switches to the new audit key");
    check(r.anchors.load().has_value() && verifyCheckpointMac(*r.anchors.load(), r.signer), "local anchor is re-MACed with the new audit key");

    r.link.queuedCommands.push_back(r.bank.signCommand(5, Action::UpdateWorkingKey, kAtmId, "Bogus|abc"));
    r.atm.processServerCommands();
    check(!r.link.commandResults.back().second, "unknown key type is refused");

    const SignedCommand overdue = r.bank.signCommand(6, Action::RestoreFromOutOfService, kAtmId);
    r.clock.advance(1801);
    r.link.queuedCommands.push_back(overdue);
    r.atm.processServerCommands();
    check(!r.link.commandResults.back().second && r.link.commandResults.back().first == 6, "a command delivered after its expiry is refused");
    SignedCommand extended = overdue;
    extended.expiresAt += 3600;
    const std::size_t reportedBefore = r.link.commandResults.size();
    r.link.queuedCommands.push_back(extended);
    r.atm.processServerCommands();
    check(r.link.commandResults.size() == reportedBefore, "extending a command's expiry breaks its signature");
    r.link.queuedCommands.push_back(r.bank.signCommand(6, Action::RestoreFromOutOfService, kAtmId));
    r.atm.processServerCommands();
    check(r.link.commandResults.back().second, "an expired command does not burn its sequence number");
}

void serviceMenuTests()
{
    section("Service menu");

    Rig eng;
    eng.type({ "E-01", kPassword.c_str(), "1", "10", "10", "10", "10", "0" });
    eng.atm.runServiceMenu();
    check(eng.cash() == 90000 + 10 * 1800, "engineer loads 10 notes of every denomination");
    const auto& engReports = eng.link.statusReports;
    check(engReports.size() == 1 && engReports[0].reason == StatusReason::CashLoaded && cashTotal(engReports[0].cassetteCounts) == eng.cash(), "CashLoaded status sent with counters");
    check(eng.link.loggedOut.size() == 1, "token revoked on exit");
    check(eng.has(EventType::STAFF_LOGIN), "staff login logged");

    Rig diag;
    diag.type({ "E-01", kPassword.c_str(), "2", "0" });
    diag.atm.runServiceMenu();
    check(diag.detailShown("HSM: Operational") && diag.detailShown("cassettes:"), "diagnostics report HSM and cassettes");

    Rig col;
    col.type({ "C-01", kPassword.c_str(), "1", "1", "2", "3", "4", "0" });
    col.atm.runServiceMenu();
    const auto& colReports = col.link.statusReports;
    const bool collected = colReports.size() == 1 && colReports[0].reason == StatusReason::CashCollected && colReports[0].cassetteCounts.at(1000) == 4 && col.cash() == 0;
    check(collected, "collector reports counted notes and cassettes are emptied");

    Rig wrong;
    wrong.type({ "E-01", "wrong-password" });
    wrong.atm.runServiceMenu();
    check(wrong.display.shown(ScreenId::AccessDenied) && wrong.link.loggedOut.empty(), "wrong password is refused");

    Rig unknown;
    unknown.type({ "NOBODY", kPassword.c_str() });
    unknown.atm.runServiceMenu();
    check(unknown.display.shown(ScreenId::AccessDenied), "unknown staff gets the same refusal");

    Rig admin;
    admin.type({ "A-01", kPassword.c_str() });
    admin.atm.runServiceMenu();
    check(admin.display.shown(ScreenId::AccessDenied), "administrators have no ATM menu");

    Rig denied;
    denied.type({ "E-01", kPassword.c_str(), "1", "10", "10", "10", "10", "0" });
    denied.access.online = false;
    denied.atm.runServiceMenu();
    check(denied.cash() == 90000 && denied.has(EventType::ACCESS_DENIED), "no decision from server means no action");

    Rig wrongRole;
    wrongRole.type({ "C-01", kPassword.c_str(), "2", "0" });
    wrongRole.atm.runServiceMenu();
    check(!wrongRole.detailShown("HSM:"), "collector cannot run engineer functions");

    Rig leak;
    leak.type({ "E-01", kPassword.c_str(), "2", "0" });
    leak.atm.runServiceMenu();
    bool found = false;
    for (const LogEvent& e : leak.events())
    {
        if (e.details.find(kPassword) != std::string::npos || e.actorId.find(kPassword) != std::string::npos) found = true;
    }
    check(!found, "password never reaches the log");

    Rig busy;
    busy.tamper.trigger();
    busy.type({ "E-01", kPassword.c_str() });
    busy.atm.runServiceMenu();
    check(busy.display.history().back() == ScreenId::OutOfService, "service menu is closed while OutOfService");

    Rig lost;
    lost.link.statusAccepted = false;
    lost.type({ "E-01", kPassword.c_str(), "1", "10", "10", "10", "10", "0" });
    lost.atm.runServiceMenu();
    check(lost.cash() == 90000 + 10 * 1800 && lost.link.statusReports.empty(), "unconfirmed load keeps the notes counted locally");
    check(lost.display.shown(ScreenId::Error) && lost.detailShown("will be resent"), "the engineer is told the server did not confirm");

    lost.insert();
    lost.type({ "1", kPin.c_str() });
    lost.atm.runSession();
    check(lost.display.history().back() == ScreenId::OutOfService && lost.bank.seen.empty(), "no client session while the server's cassette counts are stale");

    lost.link.statusAccepted = true;
    lost.atm.runSession();
    const auto& resent = lost.link.statusReports;
    check(resent.size() == 1 && resent[0].reason == StatusReason::CashLoaded && cashTotal(resent[0].cassetteCounts) == lost.cash(), "the stored report is delivered first");
    check(lost.detailShown("12340.00"), "then the waiting customer is served");

    Rig both;
    both.link.statusAccepted = false;
    both.type({ "E-01", kPassword.c_str(), "1", "1", "1", "1", "1", "0" });
    both.atm.runServiceMenu();
    both.type({ "C-01", kPassword.c_str(), "1", "1", "2", "3", "4", "0" });
    both.atm.runServiceMenu();
    both.link.statusAccepted = true;
    both.insert();
    both.type({ "1", kPin.c_str() });
    both.atm.runSession();
    const auto& ordered = both.link.statusReports;
    check(ordered.size() == 2 && ordered[0].reason == StatusReason::CashLoaded && ordered[1].reason == StatusReason::CashCollected, "queued reports are delivered in the order they happened");
}

void auditorTests()
{
    section("Auditor menu");

    Rig r;
    r.insert();
    r.type({ "1", kPin.c_str() });
    r.atm.runSession();
    r.link.checkpoint = r.checkpoints.items().back();

    r.type({ "AU-01", kPassword.c_str(), "1", "2", "1", "3", "0" });
    r.atm.runServiceMenu();
    check(r.detailShown("Log intact"), "intact log is reported as intact");
    check(r.detailShown("CARD_INSERTED"), "entry range is displayed");
    check(r.has(EventType::AUDIT_ACCESS), "auditor access is logged");

    Rig bad;
    bad.insert();
    bad.type({ "1", kPin.c_str() });
    bad.atm.runSession();
    bad.link.checkpoint = bad.checkpoints.items().back();
    auto& lines = bad.storage.lines();
    auto entry = parseEntry(lines[2]);
    LogEvent tampered = entry->getEvent();
    tampered.details = "forged";
    lines[2] = formatEntryLine(LogEntry(entry->getSeqNo(), entry->getTimestamp(), tampered, entry->getPrevHash(), entry->getHash()));
    bad.type({ "AU-01", kPassword.c_str(), "1", "0" });
    bad.atm.runServiceMenu();
    check(bad.detailShown("Log damaged"), "edited log entry is detected");

    Rig truncated;
    truncated.insert();
    truncated.type({ "1", kPin.c_str() });
    truncated.atm.runSession();
    truncated.link.checkpoint = truncated.checkpoints.items().back();
    truncated.storage.lines().resize(truncated.storage.lines().size() - 2);
    truncated.type({ "AU-01", kPassword.c_str(), "1", "0" });
    truncated.atm.runServiceMenu();
    check(truncated.detailShown("Log damaged"), "truncated log is detected through the server checkpoint");

    Rig denied;
    denied.type({ "E-01", kPassword.c_str(), "1", "0" });
    denied.atm.runServiceMenu();
    check(!denied.detailShown("Log "), "engineer cannot verify the log");
}
}

int main()
{
    gabella_test::banner("ATM test suite");
    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return 1;
    }

    stateMachineTests();
    dispenserTests();
    lifetimeAndRestartTests();
    attackTests();
    reuseAttackTests();
    withdrawalTests();
    cardAndInputTests();
    serverFailureTests();
    tamperTests();
    commandTests();
    serviceMenuTests();
    auditorTests();

    return gabella_test::summary();
}

#include "atm/AtmController.h"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>

#include "audit/VerifyResult.h"
#include "common/Invariant.h"
#include "common/PanMask.h"
#include "crypto/CryptoCore.h"
#include "crypto/SignDomain.h"

namespace
{

    constexpr std::int64_t kMaxWithdrawKop = 10000LL * 100;
    constexpr std::int64_t kStepKop = 100LL * 100;
    constexpr int kMaxPinRounds = 5;
    constexpr std::size_t kMaxEntriesShown = 20;
    const int kDenominations[] = { 100, 200, 500, 1000 };

    std::string newSessionId()
    {
        std::random_device rd;
        std::ostringstream out;
        out << std::hex << std::setfill('0');
        for (int i = 0; i < 16; ++i) out << std::setw(2) << (rd() & 0xFF);
        return out.str();
    }

    std::optional<std::uint64_t> parseNumber(const std::string& s)
    {
        if (s.empty() || s.size() > 9) return std::nullopt;
        if (!std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= '0' && c <= '9'; }))
            return std::nullopt;
        return std::stoull(s);
    }

    std::string formatKop(std::int64_t kop)
    {
        std::string fraction = std::to_string(kop % 100);
        if (fraction.size() < 2) fraction = "0" + fraction;
        return std::to_string(kop / 100) + "." + fraction;
    }

    std::string describe(const std::map<int, int>& notes)
    {
        std::string s;
        for (const auto& [value, count] : notes)
            s += std::to_string(value) + "x" + std::to_string(count) + " ";
        return s;
    }

    const char* hsmStateName(AtmHsmState s)
    {
        switch (s)
        {
        case AtmHsmState::Uninitialized: return "Uninitialized";
        case AtmHsmState::MasterInstalled: return "MasterInstalled";
        case AtmHsmState::Operational: return "OK";
        case AtmHsmState::Destroyed: return "ЗНИЩЕНО";
        }
        return "";
    }

}

AtmController::AtmController(std::string atmId, ICardReader& reader, IKeypad& keypad, IDisplay& display,
    IDispenser& dispenser, ITamperSensor& tamper, PinModule& pin, AtmHsm& hsm,
    AuditLogger& logger, const LogVerifier& verifier, IAccessClient& access,
    IServerLink& link, const IClock& clock)
    : _atmId(std::move(atmId)),
    _reader(reader),
    _keypad(keypad),
    _display(display),
    _dispenser(dispenser),
    _tamper(tamper),
    _pin(pin),
    _hsm(hsm),
    _logger(logger),
    _verifier(verifier),
    _access(access),
    _link(link),
    _clock(clock)
{
    ATM_INVARIANT(!_atmId.empty(), "atm: atmId must not be empty");
    _tamper.onTamper([this] { onTamperDetected(); });
}

AtmController::~AtmController()
{
    _tamper.onTamper(nullptr);
}

SessionState AtmController::currentState() const
{
    if (_session) return _session->getState();
    return _outOfService ? SessionState::OutOfService : SessionState::Idle;
}

bool AtmController::log(EventType type, Outcome outcome, const std::string& details,
    std::int64_t amountKop, Role role, const std::string& actorId)
{
    LogEvent e;
    e.type = type;
    e.outcome = outcome;
    e.sessionId = _session ? _session->getId() : std::string();
    e.actorRole = role;
    e.actorId = actorId;
    e.maskedPan = _session ? maskPan(_session->getCard().getPan()) : std::string();
    if (amountKop > 0) e.amount = Money::fromKop(amountKop);
    e.details = details;
    return _logger.record(e);
}

void AtmController::logQuiet(EventType type, Outcome outcome, const std::string& details,
    std::int64_t amountKop, Role role, const std::string& actorId)
{
    (void)log(type, outcome, details, amountKop, role, actorId);
}

void AtmController::step(SessionState to)
{
    ATM_INVARIANT(_session.has_value(), "atm: no active session");
    SessionStateMachine::transition(*_session, to);
}

void AtmController::runSession()
{
    if (_outOfService)
    {
        _display.show(ScreenId::OutOfService);
        return;
    }

    (void)_link.flushPending();

    auto card = _reader.readCard();
    if (!card) return;

    try
    {
        sessionFlow(*card);
    }
    catch (const IllegalTransitionError& e)
    {
        if (_session)
        {
            logQuiet(EventType::ILLEGAL_TRANSITION, Outcome::Failure, e.what());
            logQuiet(EventType::SESSION_ABORTED, Outcome::Failure, "illegal transition");
            if (SessionStateMachine::isAllowedTransition(_session->getState(), SessionState::Terminated))
                step(SessionState::Terminated);
        }
    }
    catch (const InvariantViolation& e)
    {
        logQuiet(EventType::SESSION_ABORTED, Outcome::Failure, e.what());
        enterOutOfService(false, e.what());
    }

    if (_session) endSession();
}

void AtmController::sessionFlow(const Card& cardIn)
{
    _session.emplace(newSessionId(), cardIn);
    _cardRetained = false;
    step(SessionState::CardInserted);
    logQuiet(EventType::CARD_INSERTED, Outcome::Info, "");

    const auto now = monthYear(_clock.nowUnix());
    const Card& card = _session->getCard();
    if (card.isExpired(now.first, now.second) || !card.isValidLuhn())
    {
        logQuiet(EventType::CARD_REJECTED, Outcome::Failure, "expired or invalid number");
        terminate(ScreenId::TakeCard, "card rejected");
        return;
    }

    step(SessionState::OperationSelect);
    _display.show(ScreenId::ChooseOperation);
    const auto action = _keypad.readAction();
    if (_outOfService) return;
    if (!action || !_access.isVisible(Role::Client, *action))
    {
        terminate(ScreenId::TakeCard, "no operation chosen");
        return;
    }
    _session->setAction(*action);

    if (*action == Action::Withdraw)
    {
        _display.show(ScreenId::EnterAmount);
        const auto amount = _keypad.readAmount();
        if (_outOfService) return;
        if (!amount)
        {
            terminate(ScreenId::TakeCard, "amount not entered");
            return;
        }
        if (amount->kop() > kMaxWithdrawKop)
        {
            terminate(ScreenId::LimitExceeded, "amount over limit", Outcome::Info);
            return;
        }
        if (amount->kop() <= 0 || !amount->isMultipleOf(kStepKop))
        {
            terminate(ScreenId::Error, "invalid amount");
            return;
        }
        _session->setAmountKop(amount->kop());
    }

    std::optional<AuthResponse> response;
    for (int round = 0; round < kMaxPinRounds; ++round)
    {
        step(SessionState::AwaitingPin);
        _display.show(ScreenId::EnterPin);

        std::optional<AuthRequest> request;
        {
            std::string pin;
            pin.reserve(64);
            CryptoCore::StringWiper wiper(pin);
            if (_keypad.readHiddenPin(pin) && !_outOfService)
            {
                request = _pin.processPin(card, pin, *_session->getAction(),
                    _session->getAmountKop(), _session->getId(), _atmId, _clock.nowUnix());
            }
            CryptoCore::cleanse(pin);
        }
        if (_outOfService) return;
        if (!request)
        {
            terminate(ScreenId::TakeCard, "pin entry cancelled or failed");
            return;
        }

        if (!log(EventType::AUTH_REQUESTED, Outcome::Info, "", _session->getAmountKop()))
        {
            enterOutOfService(false, "audit log unavailable");
            return;
        }

        step(SessionState::Authorizing);
        _display.show(ScreenId::Processing);
        response = _link.authorize(*request);
        if (_outOfService) return;

        if (!response || response->sessionId != _session->getId())
        {
            logQuiet(EventType::AUTH_RESULT, Outcome::Failure, "no valid server response");
            terminate(ScreenId::Error, "server unavailable or invalid response");
            return;
        }

        if (response->status == AuthStatus::WrongPin)
        {
            logQuiet(EventType::AUTH_RESULT, Outcome::Failure, "wrong pin");
            _display.show(ScreenId::WrongPin);
            response.reset();
            continue;
        }
        break;
    }

    if (!response)
    {
        terminate(ScreenId::Error, "too many pin rounds");
        return;
    }

    switch (response->status)
    {
    case AuthStatus::Approved:
        break;
    case AuthStatus::CardBlocked:
        logQuiet(EventType::AUTH_RESULT, Outcome::Failure, "card blocked");
        _reader.retain();
        _cardRetained = true;
        logQuiet(EventType::CARD_RETAINED, Outcome::Failure, "card blocked by server");
        terminate(ScreenId::CardBlocked, "card blocked");
        return;
    case AuthStatus::InsufficientFunds:
        logQuiet(EventType::AUTH_RESULT, Outcome::Info, "insufficient funds");
        terminate(ScreenId::InsufficientFunds, "insufficient funds", Outcome::Info);
        return;
    case AuthStatus::LimitExceeded:
        logQuiet(EventType::AUTH_RESULT, Outcome::Info, "limit exceeded");
        terminate(ScreenId::LimitExceeded, "limit exceeded", Outcome::Info);
        return;
    default:
        logQuiet(EventType::AUTH_RESULT, Outcome::Failure, "declined or error");
        terminate(ScreenId::Error, "declined");
        return;
    }

    logQuiet(EventType::AUTH_RESULT, Outcome::Success, "approved", _session->getAmountKop());
    step(SessionState::Approved);

    if (*_session->getAction() == Action::CheckBalance)
    {
        if (!response->balance)
        {
            terminate(ScreenId::Error, "no balance in response");
            return;
        }
        _display.show(ScreenId::ShowBalance, formatKop(response->balance->kop()) + " грн");
        (void)_keypad.readText();
        if (_outOfService) return;
        step(SessionState::Completing);
        return;
    }

    if (!response->command
        || response->command->sessionId != _session->getId()
        || response->command->amountKop != _session->getAmountKop())
    {
        terminate(ScreenId::Error, "command does not match request");
        return;
    }
    if (!SessionStateMachine::canDispense(*_session))
    {
        terminate(ScreenId::Error, "dispense not allowed");
        return;
    }

    const DispenseCommand command = *response->command;

    if (!log(EventType::DISPENSE_REQUESTED, Outcome::Info, "write-ahead", command.amountKop))
    {
        enterOutOfService(false, "audit log unavailable before dispense");
        return;
    }

    step(SessionState::Dispensing);
    const DispenseResult result = _dispenser.dispense(command);

    DispenseReport report;
    report.atmId = _atmId;
    report.sessionId = _session->getId();
    report.sequence = command.sequence;
    report.result = result;
    report.cassetteCounts = _dispenser.cassetteCounts();
    report.timestamp = _clock.nowUnix();
    _link.reportDispense(report);

    if (result == DispenseResult::Ok)
    {
        _display.show(ScreenId::TakeCash);
        logQuiet(EventType::DISPENSE_COMPLETED, Outcome::Success, "", command.amountKop);
        step(SessionState::Completing);
    }
    else
    {
        logQuiet(EventType::DISPENSE_FAILED, Outcome::Failure,
            dispenseResultToString(result), command.amountKop);
        terminate(ScreenId::Error, std::string("dispenser refused: ") + dispenseResultToString(result));
    }
}

void AtmController::terminate(ScreenId screen, const std::string& reason, Outcome outcome)
{
    if (_outOfService || !_session || _session->getState() == SessionState::OutOfService) return;

    _display.show(screen);
    logQuiet(EventType::SESSION_ABORTED, outcome, reason);
    if (_session->getState() != SessionState::Terminated) step(SessionState::Terminated);
}

void AtmController::enterOutOfService(bool retainCard, const std::string& reason)
{
    _outOfService = true;
    _retainOnShutdown = retainCard;

    if (_session && SessionStateMachine::isAllowedTransition(_session->getState(), SessionState::OutOfService))
        step(SessionState::OutOfService);

    logQuiet(EventType::SESSION_ABORTED, Outcome::Failure, "out of service: " + reason);
    _display.show(ScreenId::OutOfService);
}

void AtmController::endSession()
{
    if (!_session) return;

    const std::string sessionId = _session->getId();

    if (_outOfService)
    {
        if (_retainOnShutdown)
        {
            _reader.retain();
            logQuiet(EventType::CARD_RETAINED, Outcome::Failure, "tamper");
        }
        else
        {
            (void)_reader.eject();
            logQuiet(EventType::CARD_RETURNED, Outcome::Info, "out of service");
            _link.endSession(sessionId);
        }
        _session.reset();
        return;
    }

    if (!_cardRetained)
    {
        _display.show(ScreenId::TakeCard);
        if (_reader.eject())
        {
            logQuiet(EventType::CARD_RETURNED, Outcome::Info, "");
        }
        else
        {
            _reader.retain();
            logQuiet(EventType::CARD_RETAINED, Outcome::Info, "card not taken");
        }
    }

    _link.endSession(sessionId);
    (void)_logger.sealCheckpoint();

    if (_session->getState() != SessionState::Completing && _session->getState() != SessionState::Terminated)
        step(SessionState::Terminated);
    step(SessionState::Idle);
    _session.reset();
}

void AtmController::onTamperDetected()
{
    _dispenser.lock();
    logQuiet(EventType::TAMPER_DETECTED, Outcome::Failure, "tamper sensor triggered", 0, Role::System);
    _hsm.reportTamper();
    _keypad.disable();
    enterOutOfService(true, "tamper");
    _link.reportTamper();
}

void AtmController::processServerCommands()
{
    for (const SignedCommand& command : _link.pollCommands())
    {
        if (command.atmId != _atmId || command.commandSeq <= _lastCommandSeq) continue;

        if (!_hsm.verifyServer(SignDomain::Command, command.signedPayload(), command.signature))
        {
            logQuiet(EventType::ACCESS_DENIED, Outcome::Failure, "command signature invalid");
            continue;
        }
        _lastCommandSeq = command.commandSeq;

        bool ok = false;
        switch (command.action)
        {
        case Action::RestoreFromOutOfService:
            if (!_hsm.isDestroyed() && _hsm.state() == AtmHsmState::Operational)
            {
                _dispenser.unlock();
                _keypad.enable();
                _outOfService = false;
                _retainOnShutdown = false;
                ok = true;
            }
            break;

        case Action::UpdateWorkingKey:
        {
            const auto separator = command.params.find('|');
            if (separator == std::string::npos) break;

            const std::string type = command.params.substr(0, separator);
            KeyType keyType = KeyType::Encryption;
            if (type == "Mac") keyType = KeyType::Mac;
            else if (type == "Audit") keyType = KeyType::Audit;
            else if (type != "Encryption") break;

            ok = _hsm.updateWorkingKey(keyType, command.params.substr(separator + 1));
            if (ok)
            {
                logQuiet(EventType::KEY_UPDATED, Outcome::Success, type);
                if (keyType == KeyType::Audit) (void)_logger.sealCheckpoint();
            }
            break;
        }

        default:
            break;
        }

        logQuiet(EventType::DUAL_CONTROL_EXECUTED, ok ? Outcome::Success : Outcome::Failure,
            "command " + std::to_string(command.commandSeq));
        _link.reportCommandResult(command.commandSeq, ok);
    }
}

bool AtmController::allowed(const std::string& token, Action action)
{
    if (_access.isAllowed(token, action)) return true;

    _display.show(ScreenId::AccessDenied);
    logQuiet(EventType::ACCESS_DENIED, Outcome::Failure, "service action denied");
    return false;
}

std::optional<std::map<int, int>> AtmController::askCounts(const std::string& what)
{
    std::map<int, int> counts;
    for (int denomination : kDenominations)
    {
        _display.show(ScreenId::ServiceMenu, what + " " + std::to_string(denomination) + " грн:");
        const auto text = _keypad.readText();
        std::optional<std::uint64_t> value;
        if (text) value = parseNumber(*text);
        if (!value)
        {
            _display.show(ScreenId::Error);
            return std::nullopt;
        }
        counts[denomination] = static_cast<int>(*value);
    }
    return counts;
}

void AtmController::runServiceMenu()
{
    if (_outOfService || _session)
    {
        _display.show(ScreenId::OutOfService);
        return;
    }

    _display.show(ScreenId::ServiceMenu, "Ідентифікатор:");
    const auto staffId = _keypad.readText();
    if (!staffId) return;

    _display.show(ScreenId::ServiceMenu, "Пароль:");
    std::optional<std::string> sealed;
    {
        std::string password;
        password.reserve(64);
        CryptoCore::StringWiper wiper(password);
        if (!_keypad.readHiddenSecret(password))
        {
            CryptoCore::cleanse(password);
            return;
        }
        sealed = _hsm.sealPassword(password);
        CryptoCore::cleanse(password);
    }
    if (!sealed)
    {
        _display.show(ScreenId::Error);
        return;
    }

    const auto login = _link.staffLogin(*staffId, *sealed);
    if (!login)
    {
        _display.show(ScreenId::AccessDenied);
        return;
    }

    logQuiet(EventType::STAFF_LOGIN, Outcome::Success, "", 0, login->role, *staffId);

    switch (login->role)
    {
    case Role::ServiceEngineer: engineerMenu(login->token); break;
    case Role::CashCollector: collectorMenu(login->token); break;
    case Role::Auditor: auditorMenu(login->token); break;
    default: _display.show(ScreenId::AccessDenied); break;
    }

    _link.staffLogout(login->token);
}

void AtmController::engineerMenu(const std::string& token)
{
    for (;;)
    {
        _display.show(ScreenId::ServiceMenu, "1. Заправити касети 2. Діагностика 0. Вийти");
        const auto choice = _keypad.readText();
        if (!choice || *choice == "0") return;

        if (*choice == "1" && allowed(token, Action::LoadCash))
        {
            const auto counts = askCounts("Додати купюр");
            if (!counts) continue;

            _dispenser.loadCash(*counts);

            StatusReport report;
            report.atmId = _atmId;
            report.reason = StatusReason::CashLoaded;
            report.staffToken = token;
            report.lastExecutedSequence = _dispenser.lastSequence();
            report.cassetteCounts = _dispenser.cassetteCounts();
            report.timestamp = _clock.nowUnix();
            _link.syncStatus(report);

            logQuiet(EventType::AUDIT_ACCESS, Outcome::Success, "cash loaded", 0, Role::ServiceEngineer);
        }
        else if (*choice == "2" && allowed(token, Action::RunDiagnostics))
        {
            _display.show(ScreenId::ServiceMenu, std::string("HSM: ") + hsmStateName(_hsm.state())
                + "; касети: " + describe(_dispenser.cassetteCounts()));
        }
    }
}

void AtmController::collectorMenu(const std::string& token)
{
    for (;;)
    {
        _display.show(ScreenId::ServiceMenu, "1. Інкасація 0. Вийти");
        const auto choice = _keypad.readText();
        if (!choice || *choice == "0") return;

        if (*choice == "1" && allowed(token, Action::CollectCash))
        {
            const auto counted = askCounts("Перераховано купюр");
            if (!counted) continue;

            (void)_dispenser.unloadCash();

            StatusReport report;
            report.atmId = _atmId;
            report.reason = StatusReason::CashCollected;
            report.staffToken = token;
            report.lastExecutedSequence = _dispenser.lastSequence();
            report.cassetteCounts = *counted;
            report.timestamp = _clock.nowUnix();
            _link.syncStatus(report);

            logQuiet(EventType::AUDIT_ACCESS, Outcome::Success, "cash collected", 0, Role::CashCollector);
        }
    }
}

void AtmController::auditorMenu(const std::string& token)
{
    for (;;)
    {
        _display.show(ScreenId::ServiceMenu, "1. Перевірити журнал 2. Переглянути записи 0. Вийти");
        const auto choice = _keypad.readText();
        if (!choice || *choice == "0") return;

        if (*choice == "1" && allowed(token, Action::VerifyLog))
        {
            logQuiet(EventType::AUDIT_ACCESS, Outcome::Info, "verify", 0, Role::Auditor);

            const VerifyResult chain = _verifier.verifyChain();
            VerifyResult result = chain;
            if (chain.ok)
            {
                const auto checkpoint = _link.latestCheckpoint();
                if (checkpoint) result = _verifier.verifyAgainstCheckpoint(*checkpoint);
            }

            if (result.ok)
            {
                _display.show(ScreenId::ServiceMenu,
                    "журнал цілий, записів: " + std::to_string(chain.entryCount));
            }
            else
            {
                const std::string where = result.firstBadSeq ? std::to_string(*result.firstBadSeq) : "?";
                _display.show(ScreenId::ServiceMenu, "журнал пошкоджено з запису " + where
                    + ": " + verifyErrorToString(result.reason));
            }
        }
        else if (*choice == "2" && allowed(token, Action::ReadLog))
        {
            _display.show(ScreenId::ServiceMenu, "З запису №:");
            const auto fromText = _keypad.readText();
            _display.show(ScreenId::ServiceMenu, "По запис №:");
            const auto toText = _keypad.readText();

            std::optional<std::uint64_t> from;
            std::optional<std::uint64_t> to;
            if (fromText) from = parseNumber(*fromText);
            if (toText) to = parseNumber(*toText);
            if (!from || !to || *from > *to)
            {
                _display.show(ScreenId::Error);
                continue;
            }

            logQuiet(EventType::AUDIT_ACCESS, Outcome::Info, "read", 0, Role::Auditor);

            const auto entries = _verifier.readEntries(*from, *to);
            std::size_t shown = 0;
            for (const LogEntry& entry : entries)
            {
                if (shown++ >= kMaxEntriesShown) break;
                const LogEvent& e = entry.getEvent();
                _display.show(ScreenId::ServiceMenu, "#" + std::to_string(entry.getSeqNo()) + " "
                    + eventTypeToString(e.type) + " " + outcomeToString(e.outcome) + " " + e.details);
            }
            if (entries.empty()) _display.show(ScreenId::ServiceMenu, "записів немає");
        }
    }
}

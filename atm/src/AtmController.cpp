#include "atm/AtmController.h"

#include <algorithm>
#include <utility>

#include "audit/VerifyResult.h"
#include "common/Hex.h"
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
constexpr std::int64_t kStaffIdleSeconds = 15 * 60;
constexpr std::int64_t kStaffMaxSessionSeconds = 8 * 60 * 60;
const int kDenominations[] = { 100, 200, 500, 1000 };

std::string newSessionId()
{
    const auto bytes = CryptoCore::randomBytes(16);
    ATM_INVARIANT(bytes.has_value() && bytes->size() == 16, "atm: random source failed");
    return toHex(*bytes);
}

std::optional<std::uint64_t> parseNumber(const std::string& s)
{
    if (s.empty() || s.size() > 9) return std::nullopt;
    if (!std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) return std::nullopt;
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
    {
        if (!s.empty()) s += " ";
        s += std::to_string(value) + "x" + std::to_string(count);
    }
    return s;
}

std::string quoted(const std::string& text) { return "\"" + text + "\""; }

const char* hsmStateName(AtmHsmState s)
{
    switch (s)
    {
    case AtmHsmState::Uninitialized: return "Uninitialized";
    case AtmHsmState::MasterInstalled: return "MasterInstalled";
    case AtmHsmState::Operational: return "Operational";
    case AtmHsmState::Destroyed: return "Destroyed";
    }
    return "";
}
}

AtmController::AtmController(std::string atmId,
    ICardReader& reader,
    IKeypad& keypad,
    IDisplay& display,
    IDispenser& dispenser,
    ITamperSensor& tamper,
    PinModule& pin,
    AtmHsm& hsm,
    AuditLogger& logger,
    const LogVerifier& verifier,
    IAccessClient& access,
    IServerLink& link,
    ICounterStore& commandSeqStore,
    const IClock& clock)
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
      _commandSeqStore(commandSeqStore),
      _clock(clock)
{
    ATM_INVARIANT(!_atmId.empty(), "atm: atmId must not be empty");
    const auto stored = _commandSeqStore.load();
    _commandSeqUnreadable = !stored.has_value();
    _lastCommandSeq = stored.value_or(0);
    _tamper.onTamper([this] { onTamperDetected(); });
}

AtmController::~AtmController() { _tamper.onTamper(nullptr); }

SessionState AtmController::currentState() const
{
    if (_session) return _session->getState();
    return _outOfService ? SessionState::OutOfService : SessionState::Idle;
}

bool AtmController::log(EventType type, Outcome outcome, const std::string& details, std::int64_t amountKop, Role role, const std::string& actorId)
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

void AtmController::logQuiet(EventType type, Outcome outcome, const std::string& details, std::int64_t amountKop, Role role, const std::string& actorId)
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
    processServerCommands();

    if (_outOfService)
    {
        _display.show(ScreenId::OutOfService);
        return;
    }

    (void)_link.flushPending();
    if (!_pendingStatus.empty())
    {
        const std::size_t waiting = _pendingStatus.size();
        if (!flushStatusReports())
        {
            _display.show(ScreenId::OutOfService);
            return;
        }
        logQuiet(EventType::AUDIT_ACCESS, Outcome::Success, "status_reports_resent=" + std::to_string(waiting), 0, Role::System);
    }

    if (_syncPending) (void)syncReconnect();

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
            logQuiet(EventType::ILLEGAL_TRANSITION, Outcome::Failure, "message=" + quoted(e.what()));
            logQuiet(EventType::SESSION_ABORTED, Outcome::Failure, "reason=illegal_transition");
            if (SessionStateMachine::isAllowedTransition(_session->getState(), SessionState::Terminated)) step(SessionState::Terminated);
        }
    }
    catch (const InvariantViolation& e)
    {
        logQuiet(EventType::SESSION_ABORTED, Outcome::Failure, "reason=invariant_violation message=" + quoted(e.what()));
        enterOutOfService(false, "invariant_violation");
    }
    catch (const std::exception&)
    {
        failSafe("unexpected_exception");
    }
    catch (...)
    {
        failSafe("unexpected_exception");
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
        logQuiet(EventType::CARD_REJECTED, Outcome::Failure, "reason=expired_or_invalid");
        terminate(ScreenId::TakeCard, "card_rejected");
        return;
    }

    step(SessionState::OperationSelect);
    _display.show(ScreenId::ChooseOperation);
    const auto action = _keypad.readAction();
    if (_outOfService) return;
    if (!action || !_access.isVisible(Role::Client, *action))
    {
        terminate(ScreenId::TakeCard, "no_operation");
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
            terminate(ScreenId::TakeCard, "amount_missing");
            return;
        }
        if (amount->kop() > kMaxWithdrawKop)
        {
            terminate(ScreenId::LimitExceeded, "amount_over_limit", Outcome::Info);
            return;
        }
        if (amount->kop() <= 0 || !amount->isMultipleOf(kStepKop))
        {
            terminate(ScreenId::Error, "invalid_amount");
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
                request = _pin.processPin(card, pin, *_session->getAction(), _session->getAmountKop(), _session->getId(), _atmId, _clock.nowUnix());
            }
            CryptoCore::cleanse(pin);
        }
        if (_outOfService) return;
        if (!request)
        {
            terminate(ScreenId::TakeCard, "pin_cancelled");
            return;
        }

        if (!log(EventType::AUTH_REQUESTED, Outcome::Info, "", _session->getAmountKop()))
        {
            enterOutOfService(false, "audit_unavailable");
            return;
        }

        step(SessionState::Authorizing);
        _display.show(ScreenId::Processing);
        response = _link.authorize(*request);
        if (_outOfService) return;

        if (!response || response->sessionId != _session->getId())
        {
            _syncPending = true;
            logQuiet(EventType::AUTH_RESULT, Outcome::Failure, "reason=no_valid_response");
            terminate(ScreenId::Error, "server_unavailable");
            return;
        }

        if (response->status == AuthStatus::WrongPin)
        {
            logQuiet(EventType::AUTH_RESULT, Outcome::Failure, "status=WrongPin");
            _display.show(ScreenId::WrongPin);
            response.reset();
            continue;
        }
        break;
    }

    if (!response)
    {
        terminate(ScreenId::Error, "too_many_pin_rounds");
        return;
    }

    switch (response->status)
    {
    case AuthStatus::Approved: break;
    case AuthStatus::CardBlocked:
        logQuiet(EventType::AUTH_RESULT, Outcome::Failure, "status=CardBlocked");
        _reader.retain();
        _cardRetained = true;
        logQuiet(EventType::CARD_RETAINED, Outcome::Failure, "reason=card_blocked");
        terminate(ScreenId::CardBlocked, "card_blocked");
        return;
    case AuthStatus::InsufficientFunds:
        logQuiet(EventType::AUTH_RESULT, Outcome::Info, "status=InsufficientFunds");
        terminate(ScreenId::InsufficientFunds, "insufficient_funds", Outcome::Info);
        return;
    case AuthStatus::LimitExceeded:
        logQuiet(EventType::AUTH_RESULT, Outcome::Info, "status=LimitExceeded");
        terminate(ScreenId::LimitExceeded, "limit_exceeded", Outcome::Info);
        return;
    default:
        logQuiet(EventType::AUTH_RESULT, Outcome::Failure, std::string("status=") + authStatusToString(response->status));
        terminate(ScreenId::Error, "declined");
        return;
    }

    logQuiet(EventType::AUTH_RESULT, Outcome::Success, "status=Approved", _session->getAmountKop());
    step(SessionState::Approved);
    if (*_session->getAction() == Action::Withdraw) _holdOpen = true;

    if (*_session->getAction() == Action::CheckBalance)
    {
        if (!response->balance)
        {
            terminate(ScreenId::Error, "balance_missing");
            return;
        }
        _display.show(ScreenId::ShowBalance, formatKop(response->balance->kop()) + " UAH");
        (void)_keypad.readText();
        if (_outOfService) return;
        step(SessionState::Completing);
        return;
    }

    if (!response->command || response->command->sessionId != _session->getId() || response->command->amountKop != _session->getAmountKop())
    {
        terminate(ScreenId::Error, "command_mismatch");
        return;
    }
    if (!SessionStateMachine::canDispense(*_session))
    {
        terminate(ScreenId::Error, "dispense_not_allowed");
        return;
    }

    const DispenseCommand command = *response->command;

    if (!log(EventType::DISPENSE_REQUESTED, Outcome::Info, "phase=write_ahead", command.amountKop))
    {
        enterOutOfService(false, "audit_unavailable_before_dispense");
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
    _holdOpen = false;

    if (result == DispenseResult::Ok)
    {
        _display.show(ScreenId::TakeCash);
        logQuiet(EventType::DISPENSE_COMPLETED, Outcome::Success, "", command.amountKop);
        step(SessionState::Completing);
    }
    else
    {
        logQuiet(EventType::DISPENSE_FAILED, Outcome::Failure, std::string("result=") + dispenseResultToString(result), command.amountKop);
        terminate(ScreenId::Error, std::string("dispenser_refused result=") + dispenseResultToString(result));
    }
}

void AtmController::terminate(ScreenId screen, const std::string& reason, Outcome outcome)
{
    if (_outOfService || !_session || _session->getState() == SessionState::OutOfService) return;

    _display.show(screen);
    logQuiet(EventType::SESSION_ABORTED, outcome, "reason=" + reason);
    if (_session->getState() != SessionState::Terminated) step(SessionState::Terminated);
}

void AtmController::enterOutOfService(bool retainCard, const std::string& reason)
{
    _outOfService = true;
    _retainOnShutdown = retainCard;

    if (_session && SessionStateMachine::isAllowedTransition(_session->getState(), SessionState::OutOfService)) step(SessionState::OutOfService);

    logQuiet(EventType::SESSION_ABORTED, Outcome::Failure, "reason=out_of_service cause=" + reason);
    _display.show(ScreenId::OutOfService);
}

void AtmController::endSession()
{
    if (!_session) return;

    if (_holdOpen)
    {
        _syncPending = true;
        _holdOpen = false;
    }

    const std::string sessionId = _session->getId();

    if (_outOfService)
    {
        if (_retainOnShutdown)
        {
            _reader.retain();
            logQuiet(EventType::CARD_RETAINED, Outcome::Failure, "reason=tamper");
        }
        else
        {
            (void)_reader.eject();
            logQuiet(EventType::CARD_RETURNED, Outcome::Info, "reason=out_of_service");
        }
        _link.endSession(sessionId);
        (void)_logger.sealCheckpoint();
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
            logQuiet(EventType::CARD_RETAINED, Outcome::Info, "reason=card_not_taken");
        }
    }

    _link.endSession(sessionId);
    (void)_logger.sealCheckpoint();

    if (_session->getState() != SessionState::Completing && _session->getState() != SessionState::Terminated) step(SessionState::Terminated);
    step(SessionState::Idle);
    _session.reset();
}

void AtmController::onTamperDetected()
{
    _dispenser.lock();
    try
    {
        logQuiet(EventType::TAMPER_DETECTED, Outcome::Failure, "source=tamper_sensor", 0, Role::System);
    }
    catch (...)
    {
    }
    _hsm.reportTamper();
    _keypad.disable();
    try
    {
        enterOutOfService(true, "tamper");
    }
    catch (...)
    {
        _outOfService = true;
        _retainOnShutdown = true;
    }
    try
    {
        _link.reportTamper();
    }
    catch (...)
    {
    }
}

void AtmController::failSafe(const std::string& reason)
{
    try
    {
        logQuiet(EventType::SESSION_ABORTED, Outcome::Failure, "reason=" + reason);
        enterOutOfService(false, reason);
    }
    catch (...)
    {
        _outOfService = true;
    }
}

bool AtmController::syncReconnect()
{
    StatusReport report;
    report.atmId = _atmId;
    report.reason = StatusReason::Reconnect;
    report.lastExecutedSequence = _dispenser.lastSequence();
    report.cassetteCounts = _dispenser.cassetteCounts();
    report.timestamp = _clock.nowUnix();

    if (!_link.syncStatus(report)) return false;

    _syncPending = false;
    logQuiet(EventType::AUDIT_ACCESS, Outcome::Success, "action=Reconnect last_dispense_seq=" + std::to_string(report.lastExecutedSequence), 0, Role::System);
    return true;
}

void AtmController::processServerCommands()
{
    try
    {
        commandsFlow();
    }
    catch (const InvariantViolation& e)
    {
        logQuiet(EventType::SESSION_ABORTED, Outcome::Failure, "reason=invariant_violation message=" + quoted(e.what()));
        failSafe("invariant_violation");
    }
    catch (...)
    {
        failSafe("unexpected_exception");
    }
}

void AtmController::commandsFlow()
{
    for (const SignedCommand& command : _link.pollCommands())
    {
        if (command.atmId != _atmId || command.commandSeq <= _lastCommandSeq) continue;

        if (!_hsm.verifyServer(SignDomain::Command, command.signedPayload(), command.signature))
        {
            logQuiet(EventType::ACCESS_DENIED, Outcome::Failure, "reason=invalid_signature command_seq=" + std::to_string(command.commandSeq));
            continue;
        }
        if (_clock.nowUnix() > command.expiresAt)
        {
            logQuiet(EventType::ACCESS_DENIED, Outcome::Failure, "reason=expired command_seq=" + std::to_string(command.commandSeq));
            _link.reportCommandResult(command.commandSeq, false);
            continue;
        }
        if (_commandSeqUnreadable || !_commandSeqStore.save(command.commandSeq))
        {
            logQuiet(EventType::ACCESS_DENIED, Outcome::Failure, "reason=command_counter_unavailable command_seq=" + std::to_string(command.commandSeq));
            _link.reportCommandResult(command.commandSeq, false);
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
                _syncPending = true;
                ok = true;
            }
            break;

        case Action::UpdateWorkingKey:
        {
            const auto separator = command.params.find('|');
            if (separator == std::string::npos) break;

            const std::string type = command.params.substr(0, separator);
            KeyType keyType = KeyType::Encryption;
            if (type == "Mac")
                keyType = KeyType::Mac;
            else if (type == "Audit")
                keyType = KeyType::Audit;
            else if (type != "Encryption")
                break;

            ok = _hsm.updateWorkingKey(keyType, command.params.substr(separator + 1));
            if (ok)
            {
                logQuiet(EventType::KEY_UPDATED, Outcome::Success, "key_type=" + type);
                if (keyType == KeyType::Audit) (void)_logger.sealCheckpoint();
            }
            break;
        }

        default: break;
        }

        logQuiet(EventType::DUAL_CONTROL_EXECUTED, ok ? Outcome::Success : Outcome::Failure, "command_seq=" + std::to_string(command.commandSeq) + " action=" + actionToString(command.action));
        _link.reportCommandResult(command.commandSeq, ok);
    }
}

bool AtmController::allowed(const std::string& token, Action action)
{
    if (_access.isAllowed(token, action)) return true;

    _display.show(ScreenId::AccessDenied);
    logQuiet(EventType::ACCESS_DENIED, Outcome::Failure, std::string("action=") + actionToString(action) + " reason=denied");
    return false;
}

bool AtmController::flushStatusReports()
{
    while (!_pendingStatus.empty())
    {
        if (!_link.syncStatus(_pendingStatus.front())) return false;
        _pendingStatus.pop_front();
    }
    return true;
}

void AtmController::reportCassettes(StatusReport report, Role role, const std::string& action)
{
    _pendingStatus.push_back(std::move(report));
    if (flushStatusReports())
    {
        logQuiet(EventType::AUDIT_ACCESS, Outcome::Success, "action=" + action, 0, role);
        return;
    }
    logQuiet(EventType::AUDIT_ACCESS, Outcome::Failure, "action=" + action + " reason=status_unconfirmed", 0, role);
    _display.show(ScreenId::Error, "Server did not confirm the cassette counts; the report will be resent");
}

std::optional<std::map<int, int>> AtmController::askCounts(const std::string& what)
{
    std::map<int, int> counts;
    for (int denomination : kDenominations)
    {
        _display.show(ScreenId::ServiceMenu, what + " (" + std::to_string(denomination) + " UAH):");
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
    try
    {
        serviceMenuFlow();
    }
    catch (const InvariantViolation& e)
    {
        logQuiet(EventType::SESSION_ABORTED, Outcome::Failure, "reason=invariant_violation message=" + quoted(e.what()));
        failSafe("invariant_violation");
    }
    catch (...)
    {
        failSafe("unexpected_exception");
    }
}

bool AtmController::staffSessionLapsed(std::int64_t loginAt, std::int64_t promptAt) const
{
    const std::int64_t now = _clock.nowUnix();
    return now - promptAt > kStaffIdleSeconds || now - loginAt > kStaffMaxSessionSeconds;
}

void AtmController::staffSessionExpired()
{
    logQuiet(EventType::ACCESS_DENIED, Outcome::Failure, "reason=staff_session_expired");
    _display.show(ScreenId::ServiceMenu, "Staff session expired");
}

void AtmController::showDiagnostics()
{
    const bool linkUp = _link.flushPending();
    _display.show(ScreenId::ServiceMenu,
        std::string("HSM: ") + hsmStateName(_hsm.state()) + "; cassettes: " + describe(_dispenser.cassetteCounts()) + "; dispense_seq: " + std::to_string(_dispenser.lastSequence())
            + "; log: " + loggerStateToString(_logger.state()) + "; link: " + (linkUp ? "connected" : "unreachable") + "; sync_pending: " + (_syncPending ? "yes" : "no"));
}

void AtmController::serviceMenuFlow()
{
    if (_outOfService || _session)
    {
        _display.show(ScreenId::OutOfService);
        return;
    }

    _display.show(ScreenId::ServiceMenu, "Staff ID:");
    const auto staffId = _keypad.readText();
    if (!staffId) return;

    const auto nonce = _hsm.generateNonce();
    if (!nonce)
    {
        _display.show(ScreenId::Error);
        return;
    }

    StaffLoginRequest request;
    request.atmId = _atmId;
    request.staffId = *staffId;
    request.nonce = *nonce;
    request.timestamp = _clock.nowUnix();

    _display.show(ScreenId::ServiceMenu, "Password:");
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
        sealed = _hsm.sealPassword(password, request.binding());
        CryptoCore::cleanse(password);
    }
    if (!sealed)
    {
        _display.show(ScreenId::Error);
        return;
    }

    request.sealedPassword = *sealed;
    const auto login = _link.staffLogin(request);
    if (!login)
    {
        _display.show(ScreenId::AccessDenied);
        return;
    }

    logQuiet(EventType::STAFF_LOGIN, Outcome::Success, "", 0, login->role, *staffId);

    const std::int64_t loginAt = _clock.nowUnix();
    switch (login->role)
    {
    case Role::ServiceEngineer: engineerMenu(login->token, loginAt); break;
    case Role::CashCollector: collectorMenu(login->token, loginAt); break;
    case Role::Auditor: auditorMenu(login->token, loginAt); break;
    default: _display.show(ScreenId::AccessDenied); break;
    }

    _link.staffLogout(login->token);
}

void AtmController::engineerMenu(const std::string& token, std::int64_t loginAt)
{
    for (;;)
    {
        const std::int64_t promptAt = _clock.nowUnix();
        _display.show(ScreenId::ServiceMenu, "1 Load cassettes / 2 Diagnostics / 0 Exit");
        const auto choice = _keypad.readText();
        if (!choice || *choice == "0") return;
        if (staffSessionLapsed(loginAt, promptAt))
        {
            staffSessionExpired();
            return;
        }

        if (*choice == "1" && allowed(token, Action::LoadCash))
        {
            const auto counts = askCounts("Notes to add");
            if (!counts) continue;

            _dispenser.loadCash(*counts);

            StatusReport report;
            report.atmId = _atmId;
            report.reason = StatusReason::CashLoaded;
            report.staffToken = token;
            report.lastExecutedSequence = _dispenser.lastSequence();
            report.cassetteCounts = _dispenser.cassetteCounts();
            report.timestamp = _clock.nowUnix();
            reportCassettes(std::move(report), Role::ServiceEngineer, "LoadCash");
        }
        else if (*choice == "2" && allowed(token, Action::RunDiagnostics))
        {
            showDiagnostics();
        }
    }
}

void AtmController::collectorMenu(const std::string& token, std::int64_t loginAt)
{
    for (;;)
    {
        const std::int64_t promptAt = _clock.nowUnix();
        _display.show(ScreenId::ServiceMenu, "1 Collect cash / 0 Exit");
        const auto choice = _keypad.readText();
        if (!choice || *choice == "0") return;
        if (staffSessionLapsed(loginAt, promptAt))
        {
            staffSessionExpired();
            return;
        }

        if (*choice == "1" && allowed(token, Action::CollectCash))
        {
            const auto counted = askCounts("Notes counted");
            if (!counted) continue;

            (void)_dispenser.unloadCash();

            StatusReport report;
            report.atmId = _atmId;
            report.reason = StatusReason::CashCollected;
            report.staffToken = token;
            report.lastExecutedSequence = _dispenser.lastSequence();
            report.cassetteCounts = *counted;
            report.timestamp = _clock.nowUnix();
            reportCassettes(std::move(report), Role::CashCollector, "CollectCash");
        }
    }
}

void AtmController::auditorMenu(const std::string& token, std::int64_t loginAt)
{
    for (;;)
    {
        const std::int64_t promptAt = _clock.nowUnix();
        _display.show(ScreenId::ServiceMenu, "1 Verify log / 2 View entries / 0 Exit");
        const auto choice = _keypad.readText();
        if (!choice || *choice == "0") return;
        if (staffSessionLapsed(loginAt, promptAt))
        {
            staffSessionExpired();
            return;
        }

        if (*choice == "1" && allowed(token, Action::VerifyLog))
        {
            logQuiet(EventType::AUDIT_ACCESS, Outcome::Info, "action=VerifyLog", 0, Role::Auditor);

            const VerifyResult chain = _verifier.verifyChain();
            VerifyResult result = chain;
            bool confirmed = false;
            if (chain.ok)
            {
                const auto nonce = _hsm.generateNonce();
                const auto reply = nonce ? _link.latestCheckpoint(token, *nonce) : std::nullopt;
                if (reply)
                {
                    const bool fresh = reply->requestNonce == *nonce && reply->checkpoint.logId == _atmId;
                    if (!fresh || !_hsm.verifyServer(SignDomain::Checkpoint, reply->signedPayload(), reply->signature))
                    {
                        logQuiet(EventType::AUDIT_ACCESS, Outcome::Failure, "action=VerifyLog reason=checkpoint_unverified", 0, Role::Auditor);
                        _display.show(ScreenId::ServiceMenu, "Log could not be verified: the server checkpoint failed its signature check");
                        continue;
                    }
                    result = _verifier.verifyAgainstCheckpoint(reply->checkpoint);
                    confirmed = true;
                }
            }

            if (result.ok)
            {
                const std::string source = confirmed ? "; confirmed by the server checkpoint" : "; no server checkpoint to compare";
                _display.show(ScreenId::ServiceMenu, "Log intact, entries: " + std::to_string(chain.entryCount) + source);
            }
            else
            {
                const std::string where = result.firstBadSeq ? std::to_string(*result.firstBadSeq) : "?";
                _display.show(ScreenId::ServiceMenu, "Log damaged from entry " + where + ": " + verifyErrorToString(result.reason));
            }
        }
        else if (*choice == "2" && allowed(token, Action::ReadLog))
        {
            _display.show(ScreenId::ServiceMenu, "From entry #:");
            const auto fromText = _keypad.readText();
            _display.show(ScreenId::ServiceMenu, "To entry #:");
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

            logQuiet(EventType::AUDIT_ACCESS, Outcome::Info, "action=ReadLog from=" + std::to_string(*from) + " to=" + std::to_string(*to), 0, Role::Auditor);

            const auto entries = _verifier.readEntries(*from, *to);
            std::size_t shown = 0;
            for (const LogEntry& entry : entries)
            {
                if (shown++ >= kMaxEntriesShown) break;
                const LogEvent& e = entry.getEvent();
                _display.show(ScreenId::ServiceMenu, "#" + std::to_string(entry.getSeqNo()) + " " + eventTypeToString(e.type) + " " + outcomeToString(e.outcome) + " " + e.details);
            }
            if (entries.empty()) _display.show(ScreenId::ServiceMenu, "No entries");
        }
    }
}

#include "server/services/AuthorizationService.h"

#include <charconv>
#include <exception>
#include <utility>

#include "common/Card.h"
#include "common/PanMask.h"
#include "crypto/SignDomain.h"
#include "server/db/Statement.h"
#include "server/db/Transaction.h"

namespace
{
constexpr const char* kOpPrefix = "auth/";
constexpr const char* kPinOpPrefix = "pin/";
constexpr std::int64_t kSecondsPerDay = 24 * 60 * 60;

std::string opIdFor(const std::string& atmId, std::uint64_t sequence) { return std::string(kOpPrefix) + atmId + "/" + std::to_string(sequence); }

bool isPinOp(const std::string& opId) { return opId.compare(0, std::string(kPinOpPrefix).size(), kPinOpPrefix) == 0 && opId.size() > std::string(kPinOpPrefix).size(); }

bool advanceDispenseSeq(Database& db, const std::string& atmId, std::uint64_t expected)
{
    Statement s(db, "UPDATE atms SET last_dispense_seq = last_dispense_seq + 1 WHERE atm_id = ? AND last_dispense_seq = ?");
    s.bind(1, atmId).bind(2, static_cast<std::int64_t>(expected)).run();
    return db.changes() == 1;
}

std::optional<std::pair<std::string, std::uint64_t>> parseOpId(const std::string& opId)
{
    const std::string prefix = kOpPrefix;
    if (opId.compare(0, prefix.size(), prefix) != 0) return std::nullopt;
    const std::size_t slash = opId.rfind('/');
    if (slash == std::string::npos || slash < prefix.size() || slash + 1 >= opId.size()) return std::nullopt;

    std::uint64_t sequence = 0;
    const char* first = opId.data() + slash + 1;
    const char* last = opId.data() + opId.size();
    auto [ptr, ec] = std::from_chars(first, last, sequence);
    if (ec != std::errc() || ptr != last) return std::nullopt;
    return std::make_pair(opId.substr(prefix.size(), slash - prefix.size()), sequence);
}

bool looksLikePan(const std::string& pan)
{
    if (pan.size() < 13 || pan.size() > 19) return false;
    for (char c : pan)
        if (c < '0' || c > '9') return false;
    return true;
}

LogEvent decisionEvent(const AuthRequest& request, Outcome outcome, std::string details)
{
    LogEvent e;
    e.type = EventType::AUTH_DECISION;
    e.outcome = outcome;
    e.sessionId = request.getSessionId();
    e.actorRole = Role::System;
    e.actorId = request.getAtmId();
    if (looksLikePan(request.getPan()))
        e.maskedPan = maskPan(request.getPan());
    else
        details += " pan=invalid";
    if (request.getAction() == Action::Withdraw) e.amount = Money::fromKop(request.getAmount());
    e.details = std::string("action=") + actionToString(request.getAction()) + " " + details;
    return e;
}
}

AuthorizationService::AuthorizationService(const BankHsm& hsm,
    Database& db,
    AtmRepository& atms,
    CardRepository& cards,
    AccountRepository& accounts,
    TxRepository& transactions,
    SessionRegistry& sessions,
    IAuditSink& log,
    const IClock& clock,
    const SystemConfig& config)
    : _hsm(hsm),
      _db(db),
      _atms(atms),
      _cards(cards),
      _accounts(accounts),
      _transactions(transactions),
      _sessions(sessions),
      _log(log),
      _clock(clock),
      _config(config)
{
}

AuthResponse AuthorizationService::unavailable(const AuthRequest& request)
{
    AuthResponse response;
    response.status = AuthStatus::Error;
    response.sessionId = request.getSessionId();
    return response;
}

std::string AuthorizationService::pinOpId(const std::string& atmId) { return std::string(kPinOpPrefix) + atmId + "/" + std::to_string(_clock.nowUnix()) + "-" + std::to_string(++_pinOps); }

void AuthorizationService::closeIntent(const AuthRequest& request, const LogEvent& intent, Outcome outcome, const std::string& details)
{
    LogEvent result = intent;
    result.outcome = outcome;
    result.details = std::string("action=") + actionToString(request.getAction()) + " " + details;
    (void)_log.record(result);
}

AuthResponse AuthorizationService::refuse(const AuthRequest& request, AuthStatus status, const std::string& reason)
{
    if (!_log.record(decisionEvent(request, Outcome::Failure, std::string("status=") + authStatusToString(status) + " " + reason))) return unavailable(request);

    AuthResponse response;
    response.status = status;
    response.sessionId = request.getSessionId();
    return response;
}

AuthResponse AuthorizationService::authorize(const AuthRequest& request)
{
    const Action action = request.getAction();
    if (action != Action::CheckBalance && action != Action::Withdraw) return refuse(request, AuthStatus::Declined, "reason=unsupported_action");
    if (action == Action::CheckBalance && request.getAmount() != 0) return refuse(request, AuthStatus::Declined, "reason=invalid_amount");
    if (action == Action::Withdraw && request.getAmount() <= 0) return refuse(request, AuthStatus::Declined, "reason=invalid_amount");

    _sessions.purgeExpired();
    if (_sessions.isClosed(request.getSessionId())) return refuse(request, AuthStatus::Declined, "reason=session_closed");

    const auto card = _cards.find(request.getPan());
    if (!card) return refuse(request, AuthStatus::Declined, "reason=unknown_card");
    if (card->blocked) return refuse(request, AuthStatus::CardBlocked, "reason=card_blocked");

    const auto [month, year] = monthYear(_clock.nowUnix());
    if (Card(card->pan, card->expMonth, card->expYear).isExpired(month, year)) return refuse(request, AuthStatus::Declined, "reason=card_expired");

    if (!_hsm.verifyPin(request.getAtmId(), request.getCiphertext(), card->pan, card->pinVerifyValue, request.pinBinding())) return wrongPin(request);
    if (card->failedPinAttempts > 0 && !resetPin(request)) return unavailable(request);

    return action == Action::CheckBalance ? balance(request) : withdraw(request);
}

AuthResponse AuthorizationService::wrongPin(const AuthRequest& request)
{
    LogEvent intent = decisionEvent(request, Outcome::Info, "op=pin_failure");
    intent.opId = pinOpId(request.getAtmId());
    if (!_log.record(intent)) return unavailable(request);

    PinFailure failure;
    bool stored = false;
    try
    {
        Transaction tx(_db);
        failure = _cards.recordFailedPin(request.getPan(), _config.maxWrongPins);
        tx.commit();
        stored = true;
    }
    catch (const std::exception&)
    {
    }

    if (!stored)
    {
        closeIntent(request, intent, Outcome::Failure, "status=Error reason=storage_failure");
        return unavailable(request);
    }

    const AuthStatus status = failure.blocked ? AuthStatus::CardBlocked : AuthStatus::WrongPin;
    closeIntent(request, intent, Outcome::Failure, std::string("status=") + authStatusToString(status) + " reason=wrong_pin attempts=" + std::to_string(failure.attempts));

    AuthResponse response;
    response.status = status;
    response.sessionId = request.getSessionId();
    return response;
}

bool AuthorizationService::resetPin(const AuthRequest& request)
{
    LogEvent intent = decisionEvent(request, Outcome::Info, "op=pin_reset");
    intent.opId = pinOpId(request.getAtmId());
    if (!_log.record(intent)) return false;

    bool stored = false;
    try
    {
        Transaction tx(_db);
        _cards.resetFailedPins(request.getPan());
        tx.commit();
        stored = true;
    }
    catch (const std::exception&)
    {
    }

    closeIntent(request, intent, stored ? Outcome::Success : Outcome::Failure, stored ? "status=Reset attempts=0" : "status=Error reason=storage_failure");
    return stored;
}

AuthResponse AuthorizationService::balance(const AuthRequest& request)
{
    const auto card = _cards.find(request.getPan());
    const auto available = card ? availableKop(card->accountId) : std::nullopt;
    const auto money = available ? Money::fromKop(*available) : std::nullopt;
    if (!money) return refuse(request, AuthStatus::Error, "reason=account_unavailable");

    if (!_log.record(decisionEvent(request, Outcome::Success, "status=Approved"))) return unavailable(request);

    _sessions.open(request.getSessionId());
    AuthResponse response;
    response.status = AuthStatus::Approved;
    response.sessionId = request.getSessionId();
    response.balance = money;
    return response;
}

std::optional<std::int64_t> AuthorizationService::availableKop(const std::string& accountId) const
{
    const auto balance = _accounts.balance(accountId);
    if (!balance) return std::nullopt;
    return *balance - _transactions.reservedTotal(accountId);
}

std::optional<AuthStatus> AuthorizationService::withdrawalRefusal(const std::string& atmId, const CardRecord& card, std::int64_t amountKop, std::int64_t now, std::string& reason) const
{
    if (!_transactions.findOpenByAtm(atmId).empty())
    {
        reason = "reason=unreconciled_withdrawal";
        return AuthStatus::Declined;
    }

    const auto money = Money::fromKop(amountKop);
    if (!money || amountKop > _config.maxWithdrawalKop || !money->isMultipleOf(_config.withdrawalStepKop))
    {
        reason = "reason=limit_per_withdrawal";
        return AuthStatus::LimitExceeded;
    }

    const auto available = availableKop(card.accountId);
    if (!available)
    {
        reason = "reason=account_unavailable";
        return AuthStatus::Error;
    }

    const std::int64_t withdrawn = _transactions.dailyTotal(card.accountId, now - kSecondsPerDay);
    if (amountKop > _config.dailyWithdrawalLimitKop - withdrawn)
    {
        reason = "reason=limit_daily";
        return AuthStatus::LimitExceeded;
    }

    if (amountKop > *available)
    {
        reason = "reason=insufficient_funds";
        return AuthStatus::InsufficientFunds;
    }
    return std::nullopt;
}

AuthResponse AuthorizationService::withdraw(const AuthRequest& request)
{
    const std::int64_t now = _clock.nowUnix();

    const auto atm = _atms.find(request.getAtmId());
    const auto card = _cards.find(request.getPan());
    if (!atm || !card || atm->status != AtmStatus::Active) return refuse(request, AuthStatus::Error, "reason=state_unavailable");

    std::string reason;
    if (const auto refusal = withdrawalRefusal(request.getAtmId(), *card, request.getAmount(), now, reason)) return refuse(request, *refusal, reason);

    DispenseCommand command;
    command.atmId = request.getAtmId();
    command.sessionId = request.getSessionId();
    command.amountKop = request.getAmount();
    command.sequence = atm->lastDispenseSeq + 1;
    command.expiresAt = now + _config.dispenseCommandLifetimeSeconds;
    auto signature = _hsm.sign(SignDomain::Dispense, command.signedPayload());
    if (!signature) return refuse(request, AuthStatus::Error, "reason=signing_failed");
    command.signature = std::move(*signature);

    LogEvent intent = decisionEvent(request, Outcome::Info, "op=reserve seq=" + std::to_string(command.sequence));
    intent.opId = opIdFor(command.atmId, command.sequence);
    if (!_log.record(intent)) return unavailable(request);

    Reservation reservation;
    try
    {
        reservation = reserve(request, command, now);
    }
    catch (const std::exception&)
    {
        reservation = Reservation{};
        reservation.reason = "reason=storage_failure";
    }

    closeIntent(request, intent, reservation.done ? Outcome::Success : Outcome::Failure,
        std::string("status=") + authStatusToString(reservation.status) + " seq=" + std::to_string(command.sequence)
            + (reservation.done ? " tx=" + std::to_string(reservation.txId) : " " + reservation.reason));

    if (reservation.done) _sessions.open(request.getSessionId());
    AuthResponse response;
    response.status = reservation.status;
    response.sessionId = request.getSessionId();
    if (reservation.done) response.command = command;
    return response;
}

AuthorizationService::Reservation AuthorizationService::reserve(const AuthRequest& request, const DispenseCommand& command, std::int64_t now)
{
    Reservation reservation;
    Transaction tx(_db);

    const auto atm = _atms.find(command.atmId);
    const auto card = _cards.find(request.getPan());
    if (!atm || !card || atm->status != AtmStatus::Active || atm->lastDispenseSeq + 1 != command.sequence)
    {
        reservation.reason = "reason=state_changed";
        return reservation;
    }
    if (card->blocked)
    {
        reservation.status = AuthStatus::CardBlocked;
        reservation.reason = "reason=card_blocked";
        return reservation;
    }

    std::string reason;
    if (const auto refusal = withdrawalRefusal(command.atmId, *card, command.amountKop, now, reason))
    {
        reservation.status = *refusal;
        reservation.reason = reason;
        return reservation;
    }

    if (!advanceDispenseSeq(_db, command.atmId, atm->lastDispenseSeq))
    {
        reservation.reason = "reason=state_changed";
        return reservation;
    }

    reservation.txId = _transactions.insertHeld(command.atmId, command.sessionId, card->accountId, command.amountKop, command.sequence, now);
    tx.commit();
    reservation.done = true;
    reservation.status = AuthStatus::Approved;
    return reservation;
}

bool AuthorizationService::endSession(const std::string& atmId, const std::string& sessionId)
{
    if (!_atms.find(atmId)) return false;
    _sessions.close(sessionId);
    return true;
}

bool AuthorizationService::owns(const LogEntry& intent) const
{
    const LogEvent& e = intent.getEvent();
    return e.type == EventType::AUTH_DECISION && (parseOpId(e.opId).has_value() || isPinOp(e.opId));
}

std::optional<LogEvent> AuthorizationService::resolve(const LogEntry& intent)
{
    LogEvent result = intent.getEvent();
    if (isPinOp(result.opId))
    {
        result.outcome = Outcome::Failure;
        result.details += " recovered=unverified";
        return result;
    }

    const auto target = parseOpId(result.opId);
    if (!target) return std::nullopt;

    const bool stored = _transactions.findBySeq(target->first, target->second).has_value();
    result.outcome = stored ? Outcome::Success : Outcome::Failure;
    result.details += stored ? " recovered=committed" : " recovered=absent";
    return result;
}

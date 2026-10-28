#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "atm/DispenseResult.h"
#include "atm/ServerMessages.h"
#include "common/AuthRequest.h"
#include "crypto/BankHsm.h"
#include "crypto/CryptoCore.h"
#include "crypto/SignDomain.h"

inline std::string responsePayload(const AuthResponse& r)
{
    return CryptoCore::canonicalEncode("", {
        authStatusToString(r.status),
        r.sessionId,
        r.balance ? std::to_string(r.balance->kop()) : std::string("-"),
        r.command ? r.command->signedPayload() : std::string("-")
        });
}

class FakeBank
{
private:
    BankHsm& _hsm;
    std::string _pan;
    std::string _pinVerifyValue;
    std::set<std::string> _nonces;
    std::map<std::string, std::pair<std::string, Role>> _staff;

    bool macValid(const AuthRequest& r) const
    {
        const std::string canonical = CryptoCore::canonicalEncode("REQ:", {
            r.getAtmId(),
            r.getSessionId(),
            std::string(actionToString(r.getAction())),
            r.getCiphertext(),
            r.getNonce(),
            std::to_string(r.getTimestamp()),
            r.getPan(),
            std::to_string(r.getAmount())
            });
        return _hsm.verifyMessage(canonical, r.getMac());
    }

    AuthResponse finish(AuthResponse resp) const
    {
        if (resp.command)
        {
            resp.command->signature = *_hsm.sign(SignDomain::Dispense, resp.command->signedPayload());
        }
        resp.signature = *_hsm.sign(SignDomain::Response, responsePayload(resp));
        return resp;
    }

public:
    std::int64_t balanceKop = 1234000;
    std::int64_t heldKop = 0;
    int failedPins = 0;
    bool blocked = false;
    std::uint64_t sequence = 0;
    std::vector<AuthRequest> seen;
    std::optional<std::int64_t> commandAmountOverrideKop;

    FakeBank(BankHsm& hsm, std::string pan, const std::string& pin)
        : _hsm(hsm), _pan(std::move(pan))
    {
        _pinVerifyValue = *_hsm.computePinVerifyValue(_pan, pin);
        _staff["E-01"] = { "S3cretPass", Role::ServiceEngineer };
        _staff["C-01"] = { "S3cretPass", Role::CashCollector };
        _staff["AU-01"] = { "S3cretPass", Role::Auditor };
        _staff["A-01"] = { "S3cretPass", Role::Admin };
    }

    AuthResponse authorize(const AuthRequest& r)
    {
        seen.push_back(r);

        AuthResponse resp;
        resp.sessionId = r.getSessionId();

        if (!macValid(r) || !_nonces.insert(r.getNonce()).second)
        {
            resp.status = AuthStatus::Declined;
            return finish(resp);
        }

        if (blocked)
        {
            resp.status = AuthStatus::CardBlocked;
            return finish(resp);
        }

        if (!_hsm.verifyPin(r.getCiphertext(), r.getPan(), _pinVerifyValue))
        {
            ++failedPins;
            if (failedPins >= 3)
            {
                blocked = true;
                resp.status = AuthStatus::CardBlocked;
            }
            else
            {
                resp.status = AuthStatus::WrongPin;
            }
            return finish(resp);
        }
        failedPins = 0;

        if (r.getAction() == Action::CheckBalance)
        {
            resp.status = AuthStatus::Approved;
            resp.balance = Money::fromKop(balanceKop);
            return finish(resp);
        }

        const std::int64_t kop = r.getAmount();
        if (kop > 1000000)
        {
            resp.status = AuthStatus::LimitExceeded;
            return finish(resp);
        }
        if (kop > balanceKop)
        {
            resp.status = AuthStatus::InsufficientFunds;
            return finish(resp);
        }

        balanceKop -= kop;
        heldKop = kop;

        DispenseCommand command;
        command.atmId = r.getAtmId();
        command.sessionId = r.getSessionId();
        command.amountKop = commandAmountOverrideKop ? *commandAmountOverrideKop : kop;
        command.sequence = ++sequence;

        resp.status = AuthStatus::Approved;
        resp.command = command;
        return finish(resp);
    }

    void onDispenseReport(const DispenseReport& report)
    {
        if (report.result != DispenseResult::Ok) balanceKop += heldKop;
        heldKop = 0;
    }

    std::optional<StaffLoginResult> staffLogin(const std::string& staffId, const std::string& sealed) const
    {
        auto it = _staff.find(staffId);
        if (it == _staff.end()) return std::nullopt;

        std::string password;
        if (!_hsm.openPassword(sealed, password)) return std::nullopt;
        const bool ok = it->second.first == password;
        CryptoCore::cleanse(password);
        if (!ok) return std::nullopt;

        return StaffLoginResult{ "tok-" + staffId, it->second.second };
    }

    std::optional<Role> roleOfToken(const std::string& token) const
    {
        if (token.rfind("tok-", 0) != 0) return std::nullopt;
        auto it = _staff.find(token.substr(4));
        if (it == _staff.end()) return std::nullopt;
        return it->second.second;
    }

    SignedCommand signCommand(std::uint64_t seq, Action action, const std::string& atmId,
        const std::string& params = "") const
    {
        SignedCommand c;
        c.atmId = atmId;
        c.commandSeq = seq;
        c.action = action;
        c.params = params;
        c.signature = *_hsm.sign(SignDomain::Command, c.signedPayload());
        return c;
    }

    DispenseCommand signDispense(const std::string& atmId, std::int64_t amountKop, std::uint64_t seq,
        const std::string& sessionId = "s") const
    {
        DispenseCommand c;
        c.atmId = atmId;
        c.sessionId = sessionId;
        c.amountKop = amountKop;
        c.sequence = seq;
        c.signature = *_hsm.sign(SignDomain::Dispense, c.signedPayload());
        return c;
    }
};

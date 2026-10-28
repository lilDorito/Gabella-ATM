#pragma once
#include "atm/IAccessClient.h"
#include "FakeBank.h"

class FakeAccessClient final : public IAccessClient
{
private:
    const FakeBank& _bank;

public:
    bool online = true;

    explicit FakeAccessClient(const FakeBank& bank) : _bank(bank) {}

    static bool permits(Role role, Action action)
    {
        switch (role)
        {
        case Role::Client:
            return action == Action::CheckBalance || action == Action::Withdraw;
        case Role::ServiceEngineer:
            return action == Action::LoadCash || action == Action::RunDiagnostics;
        case Role::CashCollector:
            return action == Action::CollectCash;
        case Role::Auditor:
            return action == Action::ReadLog || action == Action::VerifyLog;
        case Role::Admin:
            return action == Action::UpdateWorkingKey || action == Action::InstallMasterKey
                || action == Action::RestoreFromOutOfService || action == Action::ResolveTransaction;
        case Role::System:
            return false;
        }
        return false;
    }

    bool isAllowed(const std::string& staffToken, Action action) override
    {
        if (!online) return false;
        auto role = _bank.roleOfToken(staffToken);
        return role && permits(*role, action);
    }

    bool isVisible(Role role, Action action) const override
    {
        return permits(role, action);
    }
};

#include "access/PermissionTable.h"

PermissionTable PermissionTable::makeDefault()
{
    std::map<Role, std::set<Action>> rules;

    rules[Role::Client] = { Action::CheckBalance, Action::Withdraw };
    rules[Role::ServiceEngineer] = { Action::LoadCash, Action::RunDiagnostics };
    rules[Role::CashCollector] = { Action::CollectCash };
    rules[Role::Auditor] = { Action::ReadLog, Action::VerifyLog };
    rules[Role::Admin] = { Action::UpdateWorkingKey, Action::InstallMasterKey, Action::RestoreFromOutOfService, Action::ResolveTransaction };

    return PermissionTable(std::move(rules));
}

bool PermissionTable::isAllowed(Role r, Action a) const
{
    const auto it = _rules.find(r);
    return it != _rules.end() && it->second.count(a) > 0;
}

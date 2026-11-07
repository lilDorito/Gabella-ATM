#include "access/AccessClient.h"

#include <utility>

#include "common/Invariant.h"

AccessClient::AccessClient(IAccessDecider& server, std::string atmId) : _server(server), _atmId(std::move(atmId)), _uiTable(PermissionTable::makeDefault())
{
    ATM_INVARIANT(!_atmId.empty(), "access client: atmId must not be empty");
}

bool AccessClient::isAllowed(const std::string& staffToken, Action action)
{
    if (staffToken.empty()) return false;

    AccessRequest request;
    request.atmId = _atmId;
    request.staffToken = staffToken;
    request.action = action;

    try
    {
        return _server.decide(request).verdict == Verdict::Allowed;
    }
    catch (...)
    {
        return false;
    }
}

bool AccessClient::isVisible(Role role, Action action) const { return _uiTable.isAllowed(role, action); }

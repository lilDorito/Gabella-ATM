#pragma once
#include <string>

#include "access/IAccessDecider.h"
#include "access/PermissionTable.h"
#include "atm/IAccessClient.h"

class AccessClient final : public IAccessClient
{
private:
    IAccessDecider& _server;
    const std::string _atmId;
    PermissionTable _uiTable;

public:
    AccessClient(IAccessDecider& server, std::string atmId);

    [[nodiscard]] bool isAllowed(const std::string& staffToken, Action action) override;

    bool isVisible(Role role, Action action) const override;
};
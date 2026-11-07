#pragma once
#include <map>
#include <set>
#include <utility>

#include "common/Action.h"
#include "common/Role.h"

class PermissionTable
{
private:
    std::map<Role, std::set<Action>> _rules;

    explicit PermissionTable(std::map<Role, std::set<Action>> rules) : _rules(std::move(rules)) {}

public:
    [[nodiscard]] static PermissionTable makeDefault();
    [[nodiscard]] bool isAllowed(Role r, Action a) const;
};

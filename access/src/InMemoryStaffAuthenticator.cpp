#include "access/IStaffAuthenticator.h"

void InMemoryStaffAuthenticator::addUser(const std::string& staffId, const std::string& password,
    Role role)
{
    _users[staffId] = Entry{ password, role };
}

std::optional<Role> InMemoryStaffAuthenticator::verify(const std::string& staffId,
    const std::string& password)
{
    const auto it = _users.find(staffId);
    if (it == _users.end()) return std::nullopt;
    if (it->second.password != password) return std::nullopt;
    return it->second.role;
}
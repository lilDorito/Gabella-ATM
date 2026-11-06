#pragma once
#include <map>
#include <optional>
#include <string>

#include "common/Role.h"

class IStaffAuthenticator
{
public:
    virtual ~IStaffAuthenticator() = default;

    [[nodiscard]] virtual std::optional<Role> verify(const std::string& staffId,
        const std::string& password) = 0;
};

class InMemoryStaffAuthenticator final : public IStaffAuthenticator
{
private:
    struct Entry
    {
        std::string password;
        Role role;
    };
    std::map<std::string, Entry> _users;

public:
    void addUser(const std::string& staffId, const std::string& password, Role role);

    [[nodiscard]] std::optional<Role> verify(const std::string& staffId,
        const std::string& password) override;
};
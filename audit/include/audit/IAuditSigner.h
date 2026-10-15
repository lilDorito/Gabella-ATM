#pragma once
#include <optional>
#include <string>

class IAuditSigner
{
public:
    virtual ~IAuditSigner() = default;
    virtual std::optional<std::string> sign(const std::string& data) const = 0;
    [[nodiscard]] virtual bool verify(const std::string& data, const std::string& mac) const = 0;
};

#pragma once
#include "audit/IAuditSigner.h"

class AtmHsm;
class BankHsm;

class AtmHsmAuditSigner final : public IAuditSigner
{
private:
    const AtmHsm& _hsm;

public:
    explicit AtmHsmAuditSigner(const AtmHsm& hsm) : _hsm(hsm) {}

    std::optional<std::string> sign(const std::string& data) const override;
    [[nodiscard]] bool verify(const std::string& data, const std::string& mac) const override;
};

class BankHsmAuditSigner final : public IAuditSigner
{
private:
    const BankHsm& _hsm;

public:
    explicit BankHsmAuditSigner(const BankHsm& hsm) : _hsm(hsm) {}

    std::optional<std::string> sign(const std::string& data) const override;
    [[nodiscard]] bool verify(const std::string& data, const std::string& mac) const override;
};

#include "audit/HsmAuditSigners.h"

#include "crypto/AtmHsm.h"
#include "crypto/BankHsm.h"
#include "crypto/CryptoCore.h"

std::optional<std::string> AtmHsmAuditSigner::sign(const std::string& data) const
{
    return _hsm.macAudit(data);
}

bool AtmHsmAuditSigner::verify(const std::string& data, const std::string& mac) const
{
    auto expected = _hsm.macAudit(data);
    if (!expected) return false;
    bool ok = CryptoCore::constantTimeEqual(*expected, mac);
    CryptoCore::cleanse(*expected);
    return ok;
}

std::optional<std::string> BankHsmAuditSigner::sign(const std::string& data) const
{
    return _hsm.macAudit(data);
}

bool BankHsmAuditSigner::verify(const std::string& data, const std::string& mac) const
{
    return _hsm.verifyAudit(data, mac);
}

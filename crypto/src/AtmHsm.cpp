#include "crypto/AtmHsm.h"

#include "common/Canonical.h"
#include "crypto/KeyWrap.h"

void AtmHsm::wipeKeys()
{
    CryptoCore::cleanse(_masterKey);
    CryptoCore::cleanse(_encKey);
    CryptoCore::cleanse(_macKey);
    CryptoCore::cleanse(_auditKey);
}

AtmHsm::~AtmHsm() { wipeKeys(); }

bool AtmHsm::installMasterKey(const std::string& masterKey)
{
    if (_state != AtmHsmState::Uninitialized && _state != AtmHsmState::Destroyed) return false;
    if (masterKey.size() != 16) return false;

    _masterKey = masterKey;
    _state = AtmHsmState::MasterInstalled;
    return true;
}

std::optional<std::string> AtmHsm::encryptPinBlock(const std::string& pinBlock, const std::string& binding) const
{
    if (_state != AtmHsmState::Operational) return std::nullopt;
    if (_encKey.size() != 16 || pinBlock.size() != 8 || binding.empty()) return std::nullopt;
    return CryptoCore::aesGcmEncrypt(_encKey, pinBlock, binding);
}

std::optional<std::string> AtmHsm::macMessage(const std::string& data) const
{
    if (_state != AtmHsmState::Operational) return std::nullopt;
    if (_macKey.size() != 16) return std::nullopt;

    return CryptoCore::hmacSha256(_macKey, data);
}

std::optional<std::string> AtmHsm::macAudit(const std::string& data) const
{
    if (_state != AtmHsmState::Operational) return std::nullopt;
    if (_auditKey.size() != 16) return std::nullopt;

    return CryptoCore::hmacSha256(_auditKey, "AUDIT:" + data);
}

bool AtmHsm::updateWorkingKey(KeyType type, const std::string& encryptedNewKey)
{
    if (_state != AtmHsmState::MasterInstalled && _state != AtmHsmState::Operational) return false;
    if (_masterKey.size() != 16) return false;

    auto plaintext = unwrapWorkingKey(_masterKey, type, encryptedNewKey);
    if (!plaintext) return false;

    switch (type)
    {
    case KeyType::Encryption: _encKey.assign(plaintext->data(), plaintext->size()); break;
    case KeyType::Mac: _macKey.assign(plaintext->data(), plaintext->size()); break;
    case KeyType::Audit: _auditKey.assign(plaintext->data(), plaintext->size()); break;
    }

    CryptoCore::cleanse(*plaintext);

    if (_encKey.size() == 16 && _macKey.size() == 16 && _auditKey.size() == 16)
    {
        _state = AtmHsmState::Operational;
    }

    return true;
}

bool AtmHsm::verifyServer(SignDomain domain, const std::string& data, const std::string& signature) const
{
    const std::string tagged = std::string(tagOf(domain)) + data;
    return CryptoCore::ed25519Verify(_serverSignPublic, tagged, signature);
}

std::optional<std::string> AtmHsm::sealPassword(const std::string& password, const std::string& binding) const
{
    if (_state != AtmHsmState::Operational || binding.empty()) return std::nullopt;
    std::string framed = canonicalEncode("PWD:", { binding, password });
    auto sealed = CryptoCore::sealedBoxSeal(_serverBoxPublic, framed);
    CryptoCore::cleanse(framed);
    return sealed;
}

std::optional<std::string> AtmHsm::generateNonce() const
{
    if (_state != AtmHsmState::Operational) return std::nullopt;

    return CryptoCore::randomBytes(16);
}

AtmHsmState AtmHsm::state() const { return _state; }

void AtmHsm::reportTamper()
{
    if (_state == AtmHsmState::Destroyed) return;

    wipeKeys();
    _state = AtmHsmState::Destroyed;
}

bool AtmHsm::isDestroyed() const { return _state == AtmHsmState::Destroyed; }

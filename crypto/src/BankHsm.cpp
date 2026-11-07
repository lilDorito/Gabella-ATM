#include "crypto/BankHsm.h"

#include <stdexcept>

#include "common/Canonical.h"
#include "crypto/KeyWrap.h"

BankHsm::BankHsm(const std::string& masterKey,
    const std::string& encKey,
    const std::string& macKey,
    const std::string& auditKey,
    const std::string& pinKey,
    std::array<unsigned char, 32> signPublic,
    std::array<unsigned char, 64> signSecret,
    std::array<unsigned char, 32> boxPublic,
    std::array<unsigned char, 32> boxSecret)
    : _masterKey(masterKey),
      _encKey(encKey),
      _macKey(macKey),
      _auditKey(auditKey),
      _pinKey(pinKey),
      _signPublic(signPublic),
      _signSecret(signSecret),
      _boxPublic(boxPublic),
      _boxSecret(boxSecret)
{
    if (masterKey.size() != 16) throw std::invalid_argument("bank hsm: masterKey must be 16 bytes");
    if (encKey.size() != 16) throw std::invalid_argument("bank hsm: encKey must be 16 bytes");
    if (macKey.size() != 16) throw std::invalid_argument("bank hsm: macKey must be 16 bytes");
    if (auditKey.size() != 16) throw std::invalid_argument("bank hsm: auditKey must be 16 bytes");
    if (pinKey.size() != 16) throw std::invalid_argument("bank hsm: pinKey must be 16 bytes");
}

BankHsm::~BankHsm() { wipeKeys(); }

void BankHsm::wipeKeys()
{
    CryptoCore::cleanse(_masterKey);
    CryptoCore::cleanse(_encKey);
    CryptoCore::cleanse(_macKey);
    CryptoCore::cleanse(_auditKey);
    CryptoCore::cleanse(_pinKey);
    CryptoCore::cleanse(_signSecret.data(), _signSecret.size());
    CryptoCore::cleanse(_boxSecret.data(), _boxSecret.size());

    for (auto& [type, key] : _pendingKeys)
    {
        CryptoCore::cleanse(key);
    }
    _pendingKeys.clear();
}

bool BankHsm::extractPin(const std::string& pinBlock, const std::string& pan, std::string& out) const
{
    if (pinBlock.size() != 8) return false;
    if (pan.size() < 13) return false;
    for (char c : pan)
        if (c < '0' || c > '9') return false;

    unsigned char nibbles[16];
    unsigned char panField[16];
    unsigned char pinField[16];
    CryptoCore::BufWiper w1(nibbles, sizeof(nibbles));
    CryptoCore::BufWiper w2(panField, sizeof(panField));
    CryptoCore::BufWiper w3(pinField, sizeof(pinField));

    for (int i = 0; i < 8; ++i)
    {
        unsigned char b = static_cast<unsigned char>(pinBlock[i]);
        nibbles[2 * i] = (b >> 4) & 0x0F;
        nibbles[2 * i + 1] = b & 0x0F;
    }

    panField[0] = panField[1] = panField[2] = panField[3] = 0;
    for (int i = 4; i < 16; ++i)
    {
        char c = pan[pan.size() - 13 + (i - 4)];
        panField[i] = static_cast<unsigned char>(c - '0');
    }

    for (int i = 0; i < 16; ++i) pinField[i] = nibbles[i] ^ panField[i];
    if (pinField[0] != 0) return false;

    int pinLen = pinField[1];
    if (pinLen < 4 || pinLen > 12) return false;

    out.clear();
    out.reserve(pinLen);
    for (int i = 0; i < pinLen; ++i)
    {
        unsigned char d = pinField[2 + i];
        if (d > 9) return false;
        out.push_back(static_cast<char>('0' + d));
    }

    for (int i = 2 + pinLen; i < 16; ++i)
    {
        if (pinField[i] != 0xF) return false;
    }

    return true;
}

bool BankHsm::verifyMessage(const std::string& data, const std::string& mac) const { return CryptoCore::hmacVerify(_macKey, data, mac); }
bool BankHsm::verifyAudit(const std::string& data, const std::string& mac) const { return CryptoCore::hmacVerify(_auditKey, "AUDIT:" + data, mac); }
std::optional<std::string> BankHsm::macAudit(const std::string& data) const { return CryptoCore::hmacSha256(_auditKey, "AUDIT:" + data); }

std::optional<std::string> BankHsm::sign(SignDomain domain, const std::string& data) const
{
    std::string tagged = std::string(tagOf(domain)) + data;
    return CryptoCore::ed25519Sign(_signSecret, tagged);
}

std::optional<std::string> BankHsm::computePinVerifyValue(const std::string& pan, const std::string& pin) const { return CryptoCore::hmacSha256(_pinKey, canonicalEncode("PIN:", { pan, pin })); }

bool BankHsm::verifyPin(const std::string& encryptedBlock, const std::string& pan, const std::string& pinVerifyValue, const std::string& binding) const
{
    if (binding.empty()) return false;
    auto decrypted = CryptoCore::aesGcmDecrypt(_encKey, encryptedBlock, binding);
    if (!decrypted) return false;

    std::string pinBlock = std::move(*decrypted);
    CryptoCore::StringWiper pinBlockWiper{ pinBlock };
    if (pinBlock.size() != 8) return false;

    std::string pin;
    CryptoCore::StringWiper pinWiper{ pin };
    if (!extractPin(pinBlock, pan, pin)) return false;

    auto computed = computePinVerifyValue(pan, pin);
    if (!computed) return false;

    bool ok = CryptoCore::constantTimeEqual(*computed, pinVerifyValue);
    CryptoCore::cleanse(*computed);

    return ok;
}

bool BankHsm::openPassword(const std::string& sealed, const std::string& binding, std::string& out) const
{
    CryptoCore::cleanse(out);
    if (binding.empty()) return false;

    std::string framed;
    CryptoCore::StringWiper framedWiper{ framed };
    if (!CryptoCore::sealedBoxOpen(_boxPublic, _boxSecret, sealed, framed)) return false;

    auto fields = canonicalDecode("PWD:", framed);
    if (!fields) return false;
    const bool bound = fields->size() == 2 && CryptoCore::constantTimeEqual((*fields)[0], binding) && !(*fields)[1].empty();
    if (bound) out = (*fields)[1];
    for (auto& field : *fields) CryptoCore::cleanse(field);
    return bound;
}

std::optional<std::string> BankHsm::prepareWorkingKey(KeyType type)
{
    if (_pendingKeys.count(type) > 0) return std::nullopt;

    auto newKey = CryptoCore::randomBytes(16);
    if (!newKey) return std::nullopt;

    auto blob = wrapWorkingKey(_masterKey, type, *newKey);
    if (!blob)
    {
        CryptoCore::cleanse(*newKey);
        return std::nullopt;
    }

    auto it = _pendingKeys.find(type);
    if (it != _pendingKeys.end())
    {
        CryptoCore::cleanse(it->second);
    }
    _pendingKeys[type] = *newKey;
    CryptoCore::cleanse(*newKey);

    return blob;
}

bool BankHsm::commitWorkingKey(KeyType type)
{
    auto it = _pendingKeys.find(type);
    if (it == _pendingKeys.end()) return false;

    std::string newKey = std::move(it->second);
    _pendingKeys.erase(it);

    switch (type)
    {
    case KeyType::Encryption: _encKey = newKey; break;
    case KeyType::Mac: _macKey = newKey; break;
    case KeyType::Audit: _auditKey = newKey; break;
    }

    CryptoCore::cleanse(newKey);
    return true;
}

bool BankHsm::cancelPendingWorkingKey(KeyType type)
{
    auto it = _pendingKeys.find(type);
    if (it == _pendingKeys.end()) return false;

    CryptoCore::cleanse(it->second);
    _pendingKeys.erase(it);
    return true;
}

std::array<unsigned char, 32> BankHsm::signPublicKey() const { return _signPublic; }
std::array<unsigned char, 32> BankHsm::boxPublicKey() const { return _boxPublic; }

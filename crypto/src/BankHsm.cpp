#include "crypto/BankHsm.h"

#include <stdexcept>
#include <utility>

#include "common/Canonical.h"
#include "crypto/KeyWrap.h"

namespace
{
constexpr std::size_t kKeySize = 16;
constexpr const char* kReservedAtmId = "SERVER";

bool sameKey(const std::string& a, const std::string& b) { return CryptoCore::constantTimeEqual(a, b); }
}

BankHsm::BankHsm(const std::string& serverKey,
    const std::string& pinKey,
    std::array<unsigned char, 32> signPublic,
    std::array<unsigned char, 64> signSecret,
    std::array<unsigned char, 32> boxPublic,
    std::array<unsigned char, 32> boxSecret)
    : _pinKey(pinKey),
      _signPublic(signPublic),
      _signSecret(signSecret),
      _boxPublic(boxPublic),
      _boxSecret(boxSecret)
{
    if (serverKey.size() != kKeySize) throw std::invalid_argument("bank hsm: serverKey must be 16 bytes");
    if (pinKey.size() != kKeySize) throw std::invalid_argument("bank hsm: pinKey must be 16 bytes");
    auto serverAuditKey = CryptoCore::hmacSha256(serverKey, "SERVER-AUDIT-KEY");
    if (!serverAuditKey) throw std::runtime_error("bank hsm: server audit key derivation failed");
    _serverAuditKey = std::move(*serverAuditKey);
}

BankHsm::~BankHsm() { wipeKeys(); }

void BankHsm::wipeKeys()
{
    CryptoCore::cleanse(_serverAuditKey);
    CryptoCore::cleanse(_pinKey);
    CryptoCore::cleanse(_signSecret.data(), _signSecret.size());
    CryptoCore::cleanse(_boxSecret.data(), _boxSecret.size());

    for (auto& [atmId, atm] : _atms)
    {
        CryptoCore::cleanse(atm.keys.masterKey);
        CryptoCore::cleanse(atm.keys.encKey);
        CryptoCore::cleanse(atm.keys.macKey);
        CryptoCore::cleanse(atm.keys.auditKey);
        for (auto& [type, key] : atm.pending) CryptoCore::cleanse(key);
        atm.pending.clear();
    }
    _atms.clear();
}

const BankHsm::AtmKeys* BankHsm::find(const std::string& atmId) const
{
    auto it = _atms.find(atmId);
    return it == _atms.end() ? nullptr : &it->second;
}

BankHsm::AtmKeys* BankHsm::find(const std::string& atmId)
{
    auto it = _atms.find(atmId);
    return it == _atms.end() ? nullptr : &it->second;
}

bool BankHsm::provisionAtm(const std::string& atmId, const AtmKeySet& keys)
{
    if (atmId.empty() || atmId == kReservedAtmId) return false;
    if (_atms.count(atmId) > 0) return false;

    const std::array<const std::string*, 4> mine{ &keys.masterKey, &keys.encKey, &keys.macKey, &keys.auditKey };
    for (const std::string* key : mine)
        if (key->size() != kKeySize) return false;

    for (std::size_t i = 0; i < mine.size(); ++i)
        for (std::size_t j = i + 1; j < mine.size(); ++j)
            if (sameKey(*mine[i], *mine[j])) return false;

    for (const auto& [otherId, other] : _atms)
    {
        const std::array<const std::string*, 4> theirs{ &other.keys.masterKey, &other.keys.encKey, &other.keys.macKey, &other.keys.auditKey };
        for (const std::string* a : mine)
            for (const std::string* b : theirs)
                if (sameKey(*a, *b)) return false;
    }

    _atms[atmId].keys = keys;
    return true;
}

bool BankHsm::hasAtm(const std::string& atmId) const { return find(atmId) != nullptr; }

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

bool BankHsm::verifyMessage(const std::string& atmId, const std::string& data, const std::string& mac) const
{
    const AtmKeys* atm = find(atmId);
    return atm && CryptoCore::hmacVerify(atm->keys.macKey, data, mac);
}

bool BankHsm::verifyAudit(const std::string& atmId, const std::string& data, const std::string& mac) const
{
    const AtmKeys* atm = find(atmId);
    return atm && CryptoCore::hmacVerify(atm->keys.auditKey, "AUDIT:" + data, mac);
}

std::optional<std::string> BankHsm::macAudit(const std::string& atmId, const std::string& data) const
{
    const AtmKeys* atm = find(atmId);
    if (!atm) return std::nullopt;
    return CryptoCore::hmacSha256(atm->keys.auditKey, "AUDIT:" + data);
}

bool BankHsm::verifyServerAudit(const std::string& data, const std::string& mac) const { return CryptoCore::hmacVerify(_serverAuditKey, "AUDIT:" + data, mac); }
std::optional<std::string> BankHsm::macServerAudit(const std::string& data) const { return CryptoCore::hmacSha256(_serverAuditKey, "AUDIT:" + data); }

std::optional<std::string> BankHsm::sign(SignDomain domain, const std::string& data) const
{
    std::string tagged = std::string(tagOf(domain)) + data;
    return CryptoCore::ed25519Sign(_signSecret, tagged);
}

std::optional<std::string> BankHsm::computePinVerifyValue(const std::string& pan, const std::string& pin) const { return CryptoCore::hmacSha256(_pinKey, canonicalEncode("PIN:", { pan, pin })); }

bool BankHsm::verifyPin(const std::string& atmId, const std::string& encryptedBlock, const std::string& pan, const std::string& pinVerifyValue, const std::string& binding) const
{
    if (binding.empty()) return false;
    const AtmKeys* atm = find(atmId);
    if (!atm) return false;
    auto decrypted = CryptoCore::aesGcmDecrypt(atm->keys.encKey, encryptedBlock, binding);
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

std::optional<std::string> BankHsm::prepareWorkingKey(const std::string& atmId, KeyType type)
{
    AtmKeys* atm = find(atmId);
    if (!atm) return std::nullopt;
    if (atm->pending.count(type) > 0) return std::nullopt;

    auto newKey = CryptoCore::randomBytes(kKeySize);
    if (!newKey) return std::nullopt;

    auto blob = wrapWorkingKey(atm->keys.masterKey, type, *newKey);
    if (!blob)
    {
        CryptoCore::cleanse(*newKey);
        return std::nullopt;
    }

    atm->pending[type] = *newKey;
    CryptoCore::cleanse(*newKey);

    return blob;
}

bool BankHsm::commitWorkingKey(const std::string& atmId, KeyType type)
{
    AtmKeys* atm = find(atmId);
    if (!atm) return false;
    auto it = atm->pending.find(type);
    if (it == atm->pending.end()) return false;

    std::string newKey = std::move(it->second);
    atm->pending.erase(it);

    switch (type)
    {
    case KeyType::Encryption: atm->keys.encKey = newKey; break;
    case KeyType::Mac: atm->keys.macKey = newKey; break;
    case KeyType::Audit: atm->keys.auditKey = newKey; break;
    }

    CryptoCore::cleanse(newKey);
    return true;
}

bool BankHsm::cancelPendingWorkingKey(const std::string& atmId, KeyType type)
{
    AtmKeys* atm = find(atmId);
    if (!atm) return false;
    auto it = atm->pending.find(type);
    if (it == atm->pending.end()) return false;

    CryptoCore::cleanse(it->second);
    atm->pending.erase(it);
    return true;
}

std::array<unsigned char, 32> BankHsm::signPublicKey() const { return _signPublic; }
std::array<unsigned char, 32> BankHsm::boxPublicKey() const { return _boxPublic; }

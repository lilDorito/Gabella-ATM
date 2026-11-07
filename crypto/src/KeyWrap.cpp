#include "crypto/KeyWrap.h"

#include "common/Canonical.h"
#include "crypto/CryptoCore.h"

namespace
{
constexpr std::size_t kKeySize = 16;
constexpr std::size_t kCipherSize = 32;
constexpr std::size_t kTagSize = 32;

const char* label(KeyType type)
{
    switch (type)
    {
    case KeyType::Encryption: return "Encryption";
    case KeyType::Mac: return "Mac";
    case KeyType::Audit: return "Audit";
    }
    return "";
}

std::optional<std::string> tagFor(const std::string& masterKey, KeyType type, const std::string& cipher)
{
    auto tagKey = CryptoCore::hmacSha256(masterKey, "KEYWRAP-TAG");
    if (!tagKey) return std::nullopt;
    auto tag = CryptoCore::hmacSha256(*tagKey, canonicalEncode("WRAP:", { label(type), cipher }));
    CryptoCore::cleanse(*tagKey);
    return tag;
}
}

std::optional<std::string> wrapWorkingKey(const std::string& masterKey, KeyType type, const std::string& key)
{
    if (masterKey.size() != kKeySize || key.size() != kKeySize) return std::nullopt;

    auto cipher = CryptoCore::aesCbcEncrypt(masterKey, key);
    if (!cipher || cipher->size() != kCipherSize) return std::nullopt;

    auto tag = tagFor(masterKey, type, *cipher);
    if (!tag) return std::nullopt;

    return *cipher + *tag;
}

std::optional<std::string> unwrapWorkingKey(const std::string& masterKey, KeyType type, const std::string& blob)
{
    if (masterKey.size() != kKeySize || blob.size() != kCipherSize + kTagSize) return std::nullopt;

    const std::string cipher = blob.substr(0, kCipherSize);
    auto expected = tagFor(masterKey, type, cipher);
    if (!expected || !CryptoCore::constantTimeEqual(*expected, blob.substr(kCipherSize))) return std::nullopt;

    auto key = CryptoCore::aesCbcDecrypt(masterKey, cipher);
    if (!key) return std::nullopt;
    if (key->size() != kKeySize)
    {
        CryptoCore::cleanse(*key);
        return std::nullopt;
    }
    return key;
}

#include "server/services/PasswordVerifier.h"

#include <sodium.h>

#include <stdexcept>

PasswordCheckFn makeArgon2idVerifier()
{
    if (sodium_init() < 0) throw std::runtime_error("libsodium cannot be initialised");
    return [](const std::string& hash, const std::string& password)
    {
        return crypto_pwhash_str_verify(hash.c_str(), password.data(), password.size()) == 0;
    };
}

std::optional<std::string> hashPasswordArgon2id(const std::string& password)
{
    if (sodium_init() < 0) return std::nullopt;
    char out[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(out, password.data(), password.size(), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) return std::nullopt;
    return std::string(out);
}

std::string makeDummyArgon2idHash()
{
    unsigned char random[24];
    randombytes_buf(random, sizeof(random));
    const std::string password(reinterpret_cast<const char*>(random), sizeof(random));
    const auto hash = hashPasswordArgon2id(password);
    if (!hash) throw std::runtime_error("cannot build the dummy password hash");
    return *hash;
}

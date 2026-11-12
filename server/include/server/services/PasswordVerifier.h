#pragma once
#include <functional>
#include <optional>
#include <string>

// hash is a libsodium "$argon2id$v=19$m=65536,t=2,p=1$..." string, as the staff table requires.
using PasswordCheckFn = std::function<bool(const std::string& hash, const std::string& password)>;

PasswordCheckFn makeArgon2idVerifier();

// Hash of a random password with the same parameters as real ones. SqliteStaffAuthenticator checks a
// login for an unknown id against it, so unknown and known ids cost the same time.
std::string makeDummyArgon2idHash();

std::optional<std::string> hashPasswordArgon2id(const std::string& password);

#pragma once
#include <functional>
#include <optional>
#include <string>

using PasswordCheckFn = std::function<bool(const std::string& hash, const std::string& password)>;

PasswordCheckFn makeArgon2idVerifier();

std::string makeDummyArgon2idHash();

std::optional<std::string> hashPasswordArgon2id(const std::string& password);

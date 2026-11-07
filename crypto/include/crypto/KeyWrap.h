#pragma once
#include <optional>
#include <string>

#include "crypto/HsmTypes.h"

[[nodiscard]] std::optional<std::string> wrapWorkingKey(const std::string& masterKey, KeyType type, const std::string& key);

[[nodiscard]] std::optional<std::string> unwrapWorkingKey(const std::string& masterKey, KeyType type, const std::string& blob);

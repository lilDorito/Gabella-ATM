#pragma once
#include <optional>
#include <string>
#include <vector>

std::string canonicalEncode(const std::string& tag, const std::vector<std::string>& fields);

std::optional<std::vector<std::string>> canonicalDecode(const std::string& tag, const std::string& encoded);

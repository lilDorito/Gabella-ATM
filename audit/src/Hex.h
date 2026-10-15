#pragma once
#include <optional>
#include <string>

std::string toHex(const std::string& bytes);
std::optional<std::string> fromHex(const std::string& hex);

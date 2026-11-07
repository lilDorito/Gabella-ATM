#include "common/Canonical.h"

std::string canonicalEncode(const std::string& tag, const std::vector<std::string>& fields)
{
    std::string out = tag;
    for (const auto& f : fields)
    {
        out += std::to_string(f.size()) + ":" + f;
    }
    return out;
}

std::optional<std::vector<std::string>> canonicalDecode(const std::string& tag, const std::string& encoded)
{
    if (encoded.compare(0, tag.size(), tag) != 0) return std::nullopt;

    std::vector<std::string> fields;
    std::size_t pos = tag.size();
    while (pos < encoded.size())
    {
        const std::size_t colon = encoded.find(':', pos);
        if (colon == std::string::npos || colon == pos || colon - pos > 9) return std::nullopt;

        std::size_t length = 0;
        for (std::size_t i = pos; i < colon; ++i)
        {
            if (encoded[i] < '0' || encoded[i] > '9') return std::nullopt;
            length = length * 10 + static_cast<std::size_t>(encoded[i] - '0');
        }
        if (length > encoded.size() - colon - 1) return std::nullopt;

        fields.push_back(encoded.substr(colon + 1, length));
        pos = colon + 1 + length;
    }
    return fields;
}

#include "atm/Terminal.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ostream>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

namespace term
{
namespace
{
const char* code(Tone tone)
{
    switch (tone)
    {
    case Tone::Plain: return "";
    case Tone::Strong: return "\033[1m";
    case Tone::Dim: return "\033[2m";
    case Tone::Accent: return "\033[36m";
    case Tone::Good: return "\033[32m";
    case Tone::Warn: return "\033[33m";
    case Tone::Bad: return "\033[31m";
    }
    return "";
}

std::string repeat(const std::string& unit, std::size_t count)
{
    std::string out;
    out.reserve(unit.size() * count);
    for (std::size_t i = 0; i < count; ++i) out += unit;
    return out;
}
}

bool prepareTerminal()
{
    const char* noColor = std::getenv("NO_COLOR");
    if (noColor && *noColor) return false;
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (handle == INVALID_HANDLE_VALUE || !GetConsoleMode(handle, &mode)) return false;
    return SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#elif defined(__unix__) || defined(__APPLE__)
    const char* termName = std::getenv("TERM");
    if (termName && std::strcmp(termName, "dumb") == 0) return false;
    return isatty(STDOUT_FILENO) != 0;
#else
    return false;
#endif
}

std::string paint(const std::string& text, Tone tone, bool color)
{
    if (!color || tone == Tone::Plain || text.empty()) return text;
    return std::string(code(tone)) + text + "\033[0m";
}

std::size_t width(const std::string& text)
{
    std::size_t columns = 0;
    for (std::size_t i = 0; i < text.size(); ++i)
    {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c == 0x1B)
        {
            while (i < text.size() && text[i] != 'm') ++i;
            continue;
        }
        if ((c & 0xC0) != 0x80) ++columns;
    }
    return columns;
}

std::string fit(const std::string& text, std::size_t columns)
{
    const std::size_t w = width(text);
    if (w <= columns) return text + std::string(columns - w, ' ');
    std::string out;
    std::size_t taken = 0;
    for (std::size_t i = 0; i < text.size(); ++i)
    {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if ((c & 0xC0) != 0x80)
        {
            if (taken + 1 >= columns) break;
            ++taken;
        }
        out += text[i];
    }
    return out + "…" + std::string(columns - taken - 1, ' ');
}

std::vector<std::string> wrap(const std::string& text, std::size_t columns)
{
    std::vector<std::string> lines;
    std::string current;
    std::size_t start = 0;
    while (start <= text.size())
    {
        std::size_t end = text.find(' ', start);
        if (end == std::string::npos) end = text.size();
        const std::string word = text.substr(start, end - start);
        if (!current.empty() && width(current) + 1 + width(word) > columns)
        {
            lines.push_back(current);
            current.clear();
        }
        if (!word.empty()) current += (current.empty() ? "" : " ") + word;
        start = end + 1;
    }
    if (!current.empty() || lines.empty()) lines.push_back(current);
    return lines;
}

std::string groupThousands(const std::string& amount)
{
    const std::size_t dot = amount.find('.');
    std::string whole = amount.substr(0, dot);
    const std::string rest = dot == std::string::npos ? "" : amount.substr(dot);
    std::string grouped;
    int count = 0;
    for (auto it = whole.rbegin(); it != whole.rend(); ++it)
    {
        if (count > 0 && count % 3 == 0) grouped.insert(grouped.begin(), ' ');
        grouped.insert(grouped.begin(), *it);
        ++count;
    }
    return grouped + rest;
}

Panel& Panel::blank()
{
    _rows.push_back(Row{});
    return *this;
}

Panel& Panel::text(const std::string& value, Tone tone)
{
    _rows.push_back(Row{ Row::Kind::Text, "", value, tone });
    return *this;
}

Panel& Panel::hint(const std::string& value) { return text(value, Tone::Dim); }

Panel& Panel::option(const std::string& key, const std::string& label)
{
    _rows.push_back(Row{ Row::Kind::Option, key, label, Tone::Plain });
    return *this;
}

Panel& Panel::pair(const std::string& key, const std::string& value, Tone tone)
{
    _rows.push_back(Row{ Row::Kind::Pair, key, value, tone });
    return *this;
}

Panel& Panel::big(const std::string& value, Tone tone)
{
    _rows.push_back(Row{ Row::Kind::Big, "", value, tone });
    return *this;
}

void Panel::render(std::ostream& out, bool color, std::size_t columns) const
{
    const std::size_t inner = columns - 2;
    const std::size_t body = inner - 4;
    const std::string bar = paint("│", _tone, color);
    const std::string label = " " + _title + " ";
    const std::size_t rest = inner > width(label) + 1 ? inner - width(label) - 1 : 0;

    out << "\n  " << paint("╭─", _tone, color) << paint(label, Tone::Strong, color) << paint(repeat("─", rest) + "╮", _tone, color) << "\n";
    out << "  " << bar << std::string(inner, ' ') << bar << "\n";
    for (const Row& row : _rows)
    {
        std::vector<std::string> cells;
        switch (row.kind)
        {
        case Row::Kind::Blank: cells.push_back(std::string(body, ' ')); break;
        case Row::Kind::Text:
        {
            const std::size_t indent = std::min(row.text.find_first_not_of(' ') == std::string::npos ? 0 : row.text.find_first_not_of(' '), body / 2);
            for (const std::string& piece : wrap(row.text.substr(indent), body - indent)) cells.push_back(std::string(indent, ' ') + paint(fit(piece, body - indent), row.tone, color));
            break;
        }
        case Row::Kind::Option: cells.push_back(paint("[" + row.key + "]", Tone::Accent, color) + "  " + fit(row.text, body - width(row.key) - 4)); break;
        case Row::Kind::Pair:
        {
            const std::size_t keyWidth = 16;
            const auto pieces = wrap(row.text, body - keyWidth);
            for (std::size_t i = 0; i < pieces.size(); ++i) cells.push_back(paint(fit(i == 0 ? row.key : "", keyWidth), Tone::Dim, color) + paint(fit(pieces[i], body - keyWidth), row.tone, color));
            break;
        }
        case Row::Kind::Big:
        {
            const std::size_t w = width(row.text);
            const std::size_t left = w < body ? (body - w) / 2 : 0;
            cells.push_back(std::string(left, ' ') + paint(paint(row.text, Tone::Strong, color), row.tone, color) + std::string(body > w + left ? body - w - left : 0, ' '));
            break;
        }
        }
        for (const std::string& cell : cells) out << "  " << bar << "  " << cell << "  " << bar << "\n";
    }
    out << "  " << bar << std::string(inner, ' ') << bar << "\n";
    out << "  " << paint("╰" + repeat("─", inner) + "╯", _tone, color) << "\n";
}

void line(std::ostream& out, const std::string& marker, const std::string& text, Tone tone, bool color)
{
    out << "  " << paint(marker, tone, color) << " " << paint(text, tone == Tone::Dim ? Tone::Dim : Tone::Plain, color) << "\n";
}

void prompt(std::ostream& out, const std::string& label, bool color)
{
    out << "  " << (label.empty() ? "" : paint(label, Tone::Dim, color) + " ") << paint("›", Tone::Accent, color) << " " << std::flush;
}
}

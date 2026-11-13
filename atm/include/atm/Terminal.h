#pragma once
#include <cstddef>
#include <iosfwd>
#include <string>
#include <vector>

namespace term
{
enum class Tone
{
    Plain,
    Strong,
    Dim,
    Accent,
    Good,
    Warn,
    Bad
};

struct Style
{
    bool framed = false;
    bool color = false;
    bool prompts = false;
};

bool prepareTerminal();
std::string paint(const std::string& text, Tone tone, bool color);
std::size_t width(const std::string& text);
std::string fit(const std::string& text, std::size_t columns);
std::vector<std::string> wrap(const std::string& text, std::size_t columns);
std::string groupThousands(const std::string& amount);

class Panel
{
private:
    struct Row
    {
        enum class Kind
        {
            Blank,
            Text,
            Option,
            Pair,
            Big
        };

        Kind kind = Kind::Blank;
        std::string key;
        std::string text;
        Tone tone = Tone::Plain;
    };

    std::string _title;
    Tone _tone;
    std::vector<Row> _rows;

public:
    explicit Panel(std::string title = "GABELLA BANK", Tone tone = Tone::Accent) : _title(std::move(title)), _tone(tone) {}

    Panel& blank();
    Panel& text(const std::string& value, Tone tone = Tone::Strong);
    Panel& hint(const std::string& value);
    Panel& option(const std::string& key, const std::string& label);
    Panel& pair(const std::string& key, const std::string& value, Tone tone = Tone::Plain);
    Panel& big(const std::string& value, Tone tone);

    void render(std::ostream& out, bool color, std::size_t columns = 52) const;
};

void line(std::ostream& out, const std::string& marker, const std::string& text, Tone tone, bool color);
void prompt(std::ostream& out, const std::string& label, bool color);
}

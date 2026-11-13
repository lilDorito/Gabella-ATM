#include "atm/DisplayEmulator.h"

#include <algorithm>
#include <cctype>

namespace
{
using term::Panel;
using term::Tone;

std::vector<std::string> split(const std::string& text, const std::string& sep)
{
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (;;)
    {
        const std::size_t at = text.find(sep, start);
        parts.push_back(text.substr(start, at == std::string::npos ? std::string::npos : at - start));
        if (at == std::string::npos) return parts;
        start = at + sep.size();
    }
}

bool isMenu(const std::vector<std::string>& items)
{
    if (items.size() < 2) return false;
    return std::all_of(items.begin(), items.end(), [](const std::string& item) { return item.size() > 2 && std::isdigit(static_cast<unsigned char>(item[0])) && item[1] == ' '; });
}

bool startsWith(const std::string& text, const std::string& prefix) { return text.compare(0, prefix.size(), prefix) == 0; }

std::string label(std::string key)
{
    if (key == "HSM") return key;
    std::replace(key.begin(), key.end(), '_', ' ');
    if (!key.empty()) key[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(key[0])));
    return key;
}

std::string counts(const std::string& value)
{
    std::string out;
    for (std::size_t i = 0; i < value.size(); ++i)
    {
        const bool between = value[i] == 'x' && i > 0 && i + 1 < value.size() && std::isdigit(static_cast<unsigned char>(value[i - 1])) && std::isdigit(static_cast<unsigned char>(value[i + 1]));
        out += between ? std::string("×") : std::string(1, value[i]);
    }
    return out;
}
}

const char* DisplayEmulator::text(ScreenId id)
{
    switch (id)
    {
    case ScreenId::Welcome: return "Insert your card";
    case ScreenId::ChooseOperation: return "1 Balance / 2 Withdraw cash / other Cancel";
    case ScreenId::EnterAmount: return "Amount (multiple of 100, up to 10000 UAH):";
    case ScreenId::EnterPin: return "Enter PIN: ****";
    case ScreenId::Processing: return "Please wait...";
    case ScreenId::ShowBalance: return "Balance:";
    case ScreenId::WrongPin: return "Wrong PIN. Please try again";
    case ScreenId::CardBlocked: return "Card retained. Please contact your bank";
    case ScreenId::AccessDenied: return "Access denied";
    case ScreenId::InsufficientFunds: return "Insufficient funds";
    case ScreenId::LimitExceeded: return "Limit exceeded";
    case ScreenId::TakeCash: return "Please take your cash";
    case ScreenId::TakeCard: return "Please take your card";
    case ScreenId::ServiceMenu: return "Service menu";
    case ScreenId::OutOfService: return "ATM temporarily out of service";
    case ScreenId::Error: return "Operation could not be completed";
    }
    return "";
}

void DisplayEmulator::show(ScreenId id, const std::string& detail)
{
    _history.push_back(id);
    _details.push_back(detail);

    if (_style.framed)
    {
        render(id, detail);
        return;
    }
    _out << "[SCREEN] " << text(id);
    if (!detail.empty()) _out << " " << detail;
    _out << "\n";
}

void DisplayEmulator::render(ScreenId id, const std::string& detail)
{
    const bool c = _style.color;
    switch (id)
    {
    case ScreenId::Welcome: Panel().text("Welcome").hint("Insert your card to begin").render(_out, c); return;
    case ScreenId::ChooseOperation:
        Panel().text("Choose an operation").blank().option("1", "Check balance").option("2", "Withdraw cash").blank().hint("Any other key cancels").render(_out, c);
        if (_style.prompts) term::prompt(_out, "", c);
        return;
    case ScreenId::EnterAmount:
        Panel().text("Enter the amount").hint("Multiples of 100 UAH, up to 10 000 UAH").render(_out, c);
        if (_style.prompts) term::prompt(_out, "UAH", c);
        return;
    case ScreenId::EnterPin:
        Panel().text("Enter your PIN").hint("4 to 12 digits, hidden as you type").render(_out, c);
        if (_style.prompts) term::prompt(_out, "PIN", c);
        return;
    case ScreenId::Processing: term::line(_out, "⋯", "Contacting the bank", Tone::Dim, c); return;
    case ScreenId::ShowBalance:
        if (_style.prompts)
        {
            Panel("GABELLA BANK", Tone::Good).text("Available balance").blank().big(term::groupThousands(detail), Tone::Good).blank().hint("Press Enter to continue").render(_out, c);
            term::prompt(_out, "", c);
            return;
        }
        Panel("GABELLA BANK", Tone::Good).text("Available balance").blank().big(term::groupThousands(detail), Tone::Good).render(_out, c);
        return;
    case ScreenId::WrongPin: Panel("GABELLA BANK", Tone::Warn).text("Wrong PIN", Tone::Warn).hint("Please try again").render(_out, c); return;
    case ScreenId::CardBlocked: Panel("GABELLA BANK", Tone::Bad).text("Card retained", Tone::Bad).hint("Please contact your bank").render(_out, c); return;
    case ScreenId::AccessDenied: Panel("GABELLA BANK", Tone::Bad).text("Access denied", Tone::Bad).render(_out, c); return;
    case ScreenId::InsufficientFunds: Panel("GABELLA BANK", Tone::Warn).text("Insufficient funds", Tone::Warn).hint("Try a smaller amount").render(_out, c); return;
    case ScreenId::LimitExceeded: Panel("GABELLA BANK", Tone::Warn).text("Limit exceeded", Tone::Warn).hint("Up to 10 000 UAH at a time and 20 000 UAH a day").render(_out, c); return;
    case ScreenId::TakeCash: Panel("GABELLA BANK", Tone::Good).text("Please take your cash", Tone::Good).render(_out, c); return;
    case ScreenId::TakeCard: term::line(_out, "▸", "Please take your card", Tone::Accent, c); return;
    case ScreenId::OutOfService: Panel("GABELLA BANK", Tone::Bad).text("Temporarily out of service", Tone::Bad).hint("Please use another ATM").render(_out, c); return;
    case ScreenId::Error:
    {
        Panel panel("GABELLA BANK", Tone::Bad);
        panel.text("Operation could not be completed", Tone::Bad);
        if (!detail.empty()) panel.hint(detail);
        panel.render(_out, c);
        return;
    }
    case ScreenId::ServiceMenu: renderService(detail); return;
    }
}

void DisplayEmulator::renderService(const std::string& detail)
{
    const bool c = _style.color;
    const auto items = split(detail, " / ");
    if (isMenu(items))
    {
        Panel panel("SERVICE MENU");
        for (const std::string& item : items) panel.option(item.substr(0, 1), item.substr(2));
        panel.render(_out, c);
        if (_style.prompts) term::prompt(_out, "", c);
        return;
    }
    if (detail == "Staff ID:")
    {
        Panel("SERVICE MODE").text("Staff sign-in").hint("Your password is sealed for the bank and hidden as you type").render(_out, c);
        if (_style.prompts) term::prompt(_out, "Staff ID", c);
        return;
    }
    if (!detail.empty() && detail.back() == ':')
    {
        if (_style.prompts)
            term::prompt(_out, detail.substr(0, detail.size() - 1), c);
        else
            term::line(_out, "·", detail.substr(0, detail.size() - 1), Tone::Dim, c);
        return;
    }
    if (startsWith(detail, "#"))
    {
        const auto words = split(detail, " ");
        const std::string outcome = words.size() > 2 ? words[2] : "";
        const Tone tone = outcome == "Success" ? Tone::Good : outcome == "Failure" ? Tone::Bad : Tone::Dim;
        std::string rest;
        for (std::size_t i = 3; i < words.size(); ++i) rest += (rest.empty() ? "" : " ") + words[i];
        _out << "  " << term::paint(term::fit(words[0], 7), Tone::Dim, c) << term::fit(words.size() > 1 ? words[1] : "", 22) << term::paint(term::fit(outcome, 9), tone, c)
             << term::paint(rest, Tone::Dim, c) << "\n";
        return;
    }
    if (startsWith(detail, "Log intact"))
    {
        Panel("LOG CHECK", Tone::Good).text(detail, Tone::Good).render(_out, c);
        return;
    }
    if (startsWith(detail, "Log damaged") || startsWith(detail, "Log could not"))
    {
        Panel("LOG CHECK", Tone::Bad).text(detail, Tone::Bad).render(_out, c);
        return;
    }
    if (detail.find("; ") != std::string::npos && detail.find(": ") != std::string::npos)
    {
        Panel panel("DIAGNOSTICS");
        for (const std::string& part : split(detail, "; "))
        {
            const std::size_t colon = part.find(": ");
            const std::string key = colon == std::string::npos ? part : part.substr(0, colon);
            const std::string value = colon == std::string::npos ? "" : part.substr(colon + 2);
            const Tone tone = value == "unreachable" || value == "yes" || value == "Failed" ? Tone::Warn : Tone::Plain;
            panel.pair(label(key), counts(value), tone);
        }
        panel.render(_out, c);
        return;
    }
    if (detail == "No entries")
    {
        term::line(_out, "·", "No entries in that range", Tone::Dim, c);
        return;
    }
    if (detail == "Staff session expired")
    {
        term::line(_out, "!", "Staff session expired, please sign in again", Tone::Warn, c);
        return;
    }
    term::line(_out, "·", detail, Tone::Plain, c);
}

bool DisplayEmulator::shown(ScreenId id) const { return std::find(_history.begin(), _history.end(), id) != _history.end(); }

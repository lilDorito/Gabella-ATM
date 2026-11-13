#include <array>
#include <cctype>
#include <map>
#include <exception>
#include <filesystem>
#include <iostream>
#include <sodium.h>
#include <sstream>
#include <string>

#include "AtmNode.h"
#include "BankNode.h"
#include "DemoData.h"
#include "atm/Terminal.h"
#include "common/Clock.h"
#include "crypto/CryptoCore.h"

namespace
{
using term::Panel;
using term::Tone;

constexpr int kOk = 0;
constexpr int kFatal = 1;
constexpr int kUsage = 2;
constexpr int kDemoFailed = 3;

const std::string kDemoAtm = "ATM-001";
const std::string kDemoRoot = "GABELLA-DEMO-KEY-ROOT";
const std::string kServerKey = "SERVERSERVERSRV1";

bool gColor = false;

void usage()
{
    std::cerr << "usage: gabella_bank [--data <dir>] [demo | atm | admin]\n"
                 "  demo    run a withdrawal, a balance check and a log audit end to end (default)\n"
                 "  atm     drive ATM-001 by hand\n"
                 "  admin   open the administrator console\n"
                 "  --data  folder for the database, logs and ATM state (default: gabella-data)\n";
}

std::array<unsigned char, 32> demoSeed(char fill)
{
    std::array<unsigned char, 32> seed{};
    seed.fill(static_cast<unsigned char>(fill));
    return seed;
}

ServerKeys demoServerKeys()
{
    ServerKeys keys;
    keys.serverKey = kServerKey;
    keys.pinKey = kDemoPinKey;
    crypto_sign_seed_keypair(keys.signPublic.data(), keys.signSecret.data(), demoSeed('S').data());
    crypto_box_seed_keypair(keys.boxPublic.data(), keys.boxSecret.data(), demoSeed('B').data());
    return keys;
}

std::string demoKey(const std::string& atmId, const char* purpose)
{
    const auto mac = CryptoCore::hmacSha256(kDemoRoot, atmId + ":" + purpose);
    if (!mac) throw std::runtime_error("app: demo key derivation failed");
    return mac->substr(0, 16);
}

AtmKeySet demoAtmKeys(const std::string& atmId) { return AtmKeySet{ demoKey(atmId, "master"), demoKey(atmId, "enc"), demoKey(atmId, "mac"), demoKey(atmId, "audit") }; }

std::string uah(std::int64_t kop) { return term::groupThousands(std::to_string(kop / 100)) + " UAH"; }

std::string masked(const std::string& pan) { return pan.size() > 4 ? "•••• " + pan.substr(pan.size() - 4) : pan; }

std::string expiry(const DemoCard& card) { return std::string(card.expMonth < 10 ? "0" : "") + std::to_string(card.expMonth) + "/" + std::to_string(card.expYear); }

std::string cassettes(const std::map<int, int>& counts)
{
    std::string out;
    for (const auto& [denomination, count] : counts) out += (out.empty() ? "" : "  ") + std::to_string(denomination) + "×" + std::to_string(count);
    return out.empty() ? "empty" : out;
}

void fail(const std::string& message) { std::cerr << "  " << term::paint("✗", Tone::Bad, gColor) << " " << message << "\n"; }

bool startBank(BankNode& bank)
{
    bank.seedIfEmpty();
    for (const std::string& atmId : demoAtms())
    {
        if (!bank.hsm.provisionAtm(atmId, demoAtmKeys(atmId)))
        {
            fail("bank HSM could not provision " + atmId);
            return false;
        }
    }

    const LoggerState state = bank.log.init();
    if (state != LoggerState::Ready)
    {
        fail(std::string("server log is ") + loggerStateToString(state) + ", refusing to start");
        return false;
    }

    const RecoveryReport recovered = bank.recover();
    bank.tick();
    std::string recovery = "nothing to finish";
    if (recovered.open > 0) recovery = std::to_string(recovered.resolved) + " unfinished operation(s) closed";
    if (recovered.failed > 0 || recovered.unowned > 0) recovery += ", " + std::to_string(recovered.failed + recovered.unowned) + " left for review";
    term::line(std::cout, "✓", "Bank online · recovery: " + recovery, recovered.failed > 0 ? Tone::Warn : Tone::Good, gColor);
    return true;
}

std::int64_t availableKop(BankNode& bank, const std::string& accountId) { return bank.accounts.balance(accountId).value_or(0) - bank.txs.reservedTotal(accountId); }

void step(int number, const std::string& title, const std::string& narration)
{
    std::cout << "\n  " << term::paint("━━ " + std::to_string(number) + " · " + title, Tone::Accent, gColor) << "\n";
    term::line(std::cout, " ", narration, Tone::Dim, gColor);
}

std::string verdict(bool ok, const std::string& text) { return std::string(ok ? "✓ " : "✗ ") + text; }

int runDemo(BankNode& bank, AtmNode& atm)
{
    const DemoCard& card = demoCards().front();
    const std::int64_t before = availableKop(bank, card.accountId);

    step(1, "Withdraw 500 UAH", "card " + masked(card.pan) + " · option 2 · amount 500 · PIN ••••");
    atm.reader.insertCard(card.pan, card.expMonth, card.expYear);
    for (const char* line : { "2", "500" }) atm.input.push(line);
    atm.input.push(card.pin);
    atm.controller.runSession();

    const auto record = bank.atms.find(kDemoAtm);
    const auto tx = record ? bank.txs.findBySeq(kDemoAtm, record->lastDispenseSeq) : std::nullopt;

    step(2, "Check the balance", "card " + masked(card.pan) + " · option 1 · PIN ••••");
    atm.reader.insertCard(card.pan, card.expMonth, card.expYear);
    atm.input.push("1");
    atm.input.push(card.pin);
    atm.controller.runSession();

    step(3, "Auditor verifies the ATM log", "service menu · staff AU-01 · option 1 (verify) · option 0 (exit)");
    for (const char* line : { "AU-01", kDemoStaffPassword, "1", "0" }) atm.input.push(line);
    atm.controller.runServiceMenu();

    bank.tick();
    const std::int64_t after = availableKop(bank, card.accountId);
    const VerifyResult atmChain = atm.verifier.verifyChain();
    const VerifyResult serverChain = LogVerifier(bank.logStorage, bank.logSigner).verifyChain();
    const auto checkpoint = bank.checkpoints.latest(kDemoAtm);

    const bool committed = tx && tx->status == TxStatus::Committed;
    const bool paidOnce = after == before - 50000;
    const bool ok = committed && paidOnce && atmChain.ok && serverChain.ok && atm.queue.empty() && checkpoint;

    Panel result("DEMO RESULT", ok ? Tone::Good : Tone::Bad);
    result.pair("Withdrawal", verdict(committed, tx ? txStatusToString(tx->status) : "missing"), committed ? Tone::Good : Tone::Bad);
    result.pair("Balance", verdict(paidOnce, uah(before) + " → " + uah(after)), paidOnce ? Tone::Good : Tone::Bad);
    result.pair("ATM log", verdict(atmChain.ok, std::to_string(atmChain.entryCount) + " entries, " + (atmChain.ok ? "chain intact" : verifyErrorToString(atmChain.reason))),
        atmChain.ok ? Tone::Good : Tone::Bad);
    result.pair("Server log", verdict(serverChain.ok, std::to_string(serverChain.entryCount) + " entries, " + (serverChain.ok ? "chain intact" : verifyErrorToString(serverChain.reason))),
        serverChain.ok ? Tone::Good : Tone::Bad);
    result.pair("Checkpoint", verdict(checkpoint.has_value(), checkpoint ? "entry #" + std::to_string(checkpoint->seqNo) + " stored by the bank" : "none stored"), checkpoint ? Tone::Good : Tone::Bad);
    result.pair("Reports queued", verdict(atm.queue.empty(), atm.queue.empty() ? "none" : std::to_string(atm.queue.size()) + " waiting"), atm.queue.empty() ? Tone::Good : Tone::Bad);
    result.blank().big(ok ? "All checks passed" : "Demo failed", ok ? Tone::Good : Tone::Bad);
    result.render(std::cout, gColor);
    std::cout << "\n";
    return ok ? kOk : kDemoFailed;
}

void showWelcome()
{
    Panel("GABELLA BANK · " + kDemoAtm).text("Terminal ready").hint("Type help for commands").render(std::cout, gColor);

    Panel cards("DEMO CARDS");
    int index = 1;
    for (const DemoCard& card : demoCards())
    {
        cards.option(std::to_string(index++), card.pan + "  " + expiry(card) + "  PIN " + card.pin);
        cards.hint("     " + std::string(card.note));
    }
    cards.blank().hint("Insert one with: card 1, card 2, …");
    cards.render(std::cout, gColor);
}

void showHelp()
{
    Panel("COMMANDS")
        .pair("card <n>", "insert demo card n")
        .pair("card <pan> …", "insert any card: card <pan> <mm> <yyyy>")
        .pair("service", "staff menu (E-01, C-01, AU-01)")
        .pair("commands", "run signed commands from the bank")
        .pair("tamper", "open the case")
        .pair("status", "show the ATM's state")
        .pair("cards", "list the demo cards")
        .pair("quit", "leave")
        .blank()
        .hint(std::string("Staff password: ") + kDemoStaffPassword + ". Admins sign in on the console only (gabella_bank admin).")
        .render(std::cout, gColor);
}

void showStatus(BankNode& bank, AtmNode& atm)
{
    const auto record = bank.atms.find(kDemoAtm);
    const bool active = record && record->status == AtmStatus::Active;
    Panel panel("STATUS", active ? Tone::Accent : Tone::Bad);
    panel.pair("Session", sessionStateToString(atm.controller.currentState()));
    panel.pair("Bank says", record ? atmStatusToString(record->status) : "unknown", active ? Tone::Good : Tone::Bad);
    panel.pair("Cassettes", cassettes(atm.dispenser.cassetteCounts()));
    panel.pair("Reports queued", atm.queue.empty() ? "none" : std::to_string(atm.queue.size()), atm.queue.empty() ? Tone::Plain : Tone::Warn);
    if (record && record->logReviewRequired) panel.pair("Log", "flagged for review", Tone::Warn);
    panel.render(std::cout, gColor);
}

bool insertCard(AtmNode& atm, std::istringstream& words)
{
    std::string first;
    if (!(words >> first)) return false;
    const auto& cards = demoCards();
    if (first.size() <= 2 && !first.empty() && std::isdigit(static_cast<unsigned char>(first[0])))
    {
        const std::size_t index = static_cast<std::size_t>(std::stoi(first));
        if (index < 1 || index > cards.size()) return false;
        const DemoCard& card = cards[index - 1];
        atm.reader.insertCard(card.pan, card.expMonth, card.expYear);
        return true;
    }
    int month = 0;
    int year = 0;
    if (!(words >> month >> year)) return false;
    atm.reader.insertCard(first, month, year);
    return true;
}

int runAtm(BankNode& bank, AtmNode& atm)
{
    showWelcome();
    std::string line;
    while (std::cout << "\n", term::prompt(std::cout, "atm", gColor), std::getline(std::cin, line))
    {
        std::istringstream words(line);
        std::string cmd;
        words >> cmd;
        if (cmd.empty()) continue;

        if (cmd == "quit" || cmd == "exit") break;
        if (cmd == "help")
        {
            showHelp();
        }
        else if (cmd == "cards")
        {
            showWelcome();
        }
        else if (cmd == "card")
        {
            if (!insertCard(atm, words))
            {
                term::line(std::cout, "!", "Usage: card <n> or card <pan> <mm> <yyyy>", Tone::Warn, gColor);
                continue;
            }
            atm.controller.runSession();
        }
        else if (cmd == "service")
        {
            atm.controller.runServiceMenu();
        }
        else if (cmd == "commands")
        {
            atm.controller.processServerCommands();
            showStatus(bank, atm);
        }
        else if (cmd == "tamper")
        {
            atm.tamper.trigger();
            term::line(std::cout, "!", "Case opened: keys wiped, dispenser locked, bank notified", Tone::Bad, gColor);
        }
        else if (cmd == "status")
        {
            showStatus(bank, atm);
        }
        else
        {
            term::line(std::cout, "!", "Unknown command \"" + cmd + "\". Type help.", Tone::Warn, gColor);
        }
        bank.tick();
    }
    std::cout << "\n";
    return kOk;
}
}

int main(int argc, char** argv)
{
    std::filesystem::path dataDir = "gabella-data";
    std::string mode = "demo";
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--data" && i + 1 < argc)
        {
            dataDir = argv[++i];
        }
        else if (arg == "demo" || arg == "atm" || arg == "admin")
        {
            mode = arg;
        }
        else
        {
            usage();
            return kUsage;
        }
    }

    try
    {
        gColor = term::prepareTerminal();
        if (!CryptoCore::init())
        {
            fail("libsodium initialization failed");
            return kFatal;
        }
        std::filesystem::create_directories(dataDir / "logs");

        SystemClock clock;
        const ServerKeys keys = demoServerKeys();
        BankNode bank(clock, keys, dataDir);
        if (!startBank(bank)) return kFatal;

        if (mode == "admin") return bank.console.run(std::cin, std::cout);

        const term::Style style{ true, gColor, mode == "atm" };
        AtmNode atm(kDemoAtm, clock, bank.server, keys.signPublic, keys.boxPublic, demoAtmKeys(kDemoAtm), bank.cassettes.expected(kDemoAtm), dataDir, bank.config.checkpointInterval, mode == "demo", style);
        const LoggerState atmLog = atm.log.init();
        if (atmLog != LoggerState::Ready) term::line(std::cout, "!", std::string("ATM log is ") + loggerStateToString(atmLog) + ", the ATM will stay out of service", Tone::Bad, gColor);

        return mode == "demo" ? runDemo(bank, atm) : runAtm(bank, atm);
    }
    catch (const std::exception& e)
    {
        fail(e.what());
        return kFatal;
    }
}

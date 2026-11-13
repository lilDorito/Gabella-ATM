#include <array>
#include <exception>
#include <filesystem>
#include <iostream>
#include <sodium.h>
#include <sstream>
#include <string>

#include "AtmNode.h"
#include "BankNode.h"
#include "DemoData.h"
#include "common/Clock.h"
#include "crypto/CryptoCore.h"

namespace
{
constexpr int kOk = 0;
constexpr int kFatal = 1;
constexpr int kUsage = 2;
constexpr int kDemoFailed = 3;

const std::string kDemoAtm = "ATM-001";
const std::string kDemoRoot = "GABELLA-DEMO-KEY-ROOT";
const std::string kServerKey = "SERVERSERVERSRV1";

void usage()
{
    std::cerr << "usage: gabella_bank [--data <dir>] [demo | atm | admin]\n"
                 "  demo    run a withdrawal, a balance check and a log audit end to end (default)\n"
                 "  atm     drive ATM-001 by hand: card <pan> <mm> <yyyy>, service, commands, tamper, status, quit\n"
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

std::string uah(std::int64_t kop) { return std::to_string(kop / 100) + " UAH"; }

bool startBank(BankNode& bank)
{
    bank.seedIfEmpty();
    for (const std::string& atmId : demoAtms())
    {
        if (!bank.hsm.provisionAtm(atmId, demoAtmKeys(atmId)))
        {
            std::cerr << "fatal: bank HSM could not provision " << atmId << "\n";
            return false;
        }
    }

    const LoggerState state = bank.log.init();
    if (state != LoggerState::Ready)
    {
        std::cerr << "fatal: server log is " << loggerStateToString(state) << ", refusing to start\n";
        return false;
    }

    const RecoveryReport recovered = bank.recover();
    std::cout << "server: recovery open=" << recovered.open << " resolved=" << recovered.resolved << " unowned=" << recovered.unowned << " failed=" << recovered.failed << "\n";
    bank.tick();
    return true;
}

std::int64_t availableKop(BankNode& bank, const std::string& accountId) { return bank.accounts.balance(accountId).value_or(0) - bank.txs.reservedTotal(accountId); }

int runDemo(BankNode& bank, AtmNode& atm)
{
    const DemoCard& card = demoCards().front();
    const std::int64_t before = availableKop(bank, card.accountId);

    std::cout << "\n--- withdrawal of 500 UAH ---\n";
    atm.reader.insertCard(card.pan, card.expMonth, card.expYear);
    for (const char* line : { "2", "500" }) atm.input.push(line);
    atm.input.push(card.pin);
    atm.controller.runSession();

    const auto record = bank.atms.find(kDemoAtm);
    const auto tx = record ? bank.txs.findBySeq(kDemoAtm, record->lastDispenseSeq) : std::nullopt;

    std::cout << "\n--- balance check ---\n";
    atm.reader.insertCard(card.pan, card.expMonth, card.expYear);
    atm.input.push("1");
    atm.input.push(card.pin);
    atm.controller.runSession();

    std::cout << "\n--- auditor verifies the log ---\n";
    for (const char* line : { "AU-01", kDemoStaffPassword, "1", "0" }) atm.input.push(line);
    atm.controller.runServiceMenu();

    bank.tick();
    const std::int64_t after = availableKop(bank, card.accountId);
    const VerifyResult atmChain = atm.verifier.verifyChain();
    const VerifyResult serverChain = LogVerifier(bank.logStorage, bank.logSigner).verifyChain();
    const auto checkpoint = bank.checkpoints.latest(kDemoAtm);

    std::cout << "\n--- result ---\n";
    std::cout << "withdrawal: status=" << (tx ? txStatusToString(tx->status) : "missing") << " balance_before=" << uah(before) << " balance_after=" << uah(after) << "\n";
    std::cout << "atm_log: entries=" << atmChain.entryCount << " chain=" << (atmChain.ok ? "ok" : verifyErrorToString(atmChain.reason)) << " pending_reports=" << atm.queue.size() << "\n";
    std::cout << "server_log: entries=" << serverChain.entryCount << " chain=" << (serverChain.ok ? "ok" : verifyErrorToString(serverChain.reason))
              << " atm_checkpoint_seq=" << (checkpoint ? checkpoint->seqNo : 0) << "\n";

    const bool ok = tx && tx->status == TxStatus::Committed && after == before - 50000 && atmChain.ok && serverChain.ok && atm.queue.empty() && checkpoint;
    std::cout << (ok ? "demo: ok\n" : "demo: FAILED\n");
    return ok ? kOk : kDemoFailed;
}

void atmHelp()
{
    std::cout << "commands:\n"
                 "  card <pan> <mm> <yyyy>   insert a card and start a session\n"
                 "  service                  open the service menu\n"
                 "  commands                 fetch and run signed commands from the bank\n"
                 "  tamper                   open the case\n"
                 "  status                   show the ATM's state\n"
                 "  quit\n";
}

void demoHelp()
{
    std::cout << "demo cards:\n";
    for (const DemoCard& card : demoCards())
        std::cout << "  card " << card.pan << " " << (card.expMonth < 10 ? "0" : "") << card.expMonth << " " << card.expYear << "   PIN " << card.pin << "   " << card.note << "\n";
    std::cout << "staff: E-01 engineer, C-01 collector, AU-01 auditor, A-01..A-03 admins (console only), password " << kDemoStaffPassword << "\n";
}

int runAtm(BankNode& bank, AtmNode& atm)
{
    std::cout << "ATM " << kDemoAtm << " ready. Type help.\n";
    demoHelp();
    std::string line;
    while (std::cout << "atm> " << std::flush, std::getline(std::cin, line))
    {
        std::istringstream words(line);
        std::string cmd;
        words >> cmd;
        if (cmd.empty()) continue;

        if (cmd == "quit" || cmd == "exit") break;
        if (cmd == "help")
        {
            atmHelp();
            demoHelp();
        }
        else if (cmd == "card")
        {
            std::string pan;
            int month = 0;
            int year = 0;
            if (!(words >> pan >> month >> year))
            {
                std::cout << "usage: card <pan> <mm> <yyyy>\n";
                continue;
            }
            atm.reader.insertCard(pan, month, year);
            atm.controller.runSession();
        }
        else if (cmd == "service")
        {
            atm.controller.runServiceMenu();
        }
        else if (cmd == "commands")
        {
            atm.controller.processServerCommands();
        }
        else if (cmd == "tamper")
        {
            atm.tamper.trigger();
        }
        else if (cmd == "status")
        {
            const auto record = bank.atms.find(kDemoAtm);
            std::cout << "atm: state=" << sessionStateToString(atm.controller.currentState()) << " server_status=" << (record ? atmStatusToString(record->status) : "unknown")
                      << " pending_reports=" << atm.queue.size() << "\n";
        }
        else
        {
            std::cout << "unknown command, type help\n";
        }
        bank.tick();
    }
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
        if (!CryptoCore::init())
        {
            std::cerr << "fatal: libsodium initialization failed\n";
            return kFatal;
        }
        std::filesystem::create_directories(dataDir / "logs");

        SystemClock clock;
        const ServerKeys keys = demoServerKeys();
        BankNode bank(clock, keys, dataDir);
        if (!startBank(bank)) return kFatal;

        if (mode == "admin") return bank.console.run(std::cin, std::cout);

        AtmNode atm(kDemoAtm, clock, bank.server, keys.signPublic, keys.boxPublic, demoAtmKeys(kDemoAtm), bank.cassettes.expected(kDemoAtm), dataDir, bank.config.checkpointInterval, mode == "demo");
        const LoggerState atmLog = atm.log.init();
        if (atmLog != LoggerState::Ready) std::cout << "atm: log is " << loggerStateToString(atmLog) << ", the ATM will stay out of service\n";

        return mode == "demo" ? runDemo(bank, atm) : runAtm(bank, atm);
    }
    catch (const std::exception& e)
    {
        std::cerr << "fatal: " << e.what() << "\n";
        return kFatal;
    }
}

#include <array>
#include <exception>
#include <filesystem>
#include <iostream>
#include <sodium.h>
#include <stdexcept>
#include <string>

#include "DemoData.h"
#include "crypto/BankHsm.h"
#include "crypto/CryptoCore.h"
#include "server/db/Database.h"

namespace
{
constexpr int kOk = 0;
constexpr int kFailed = 1;
constexpr int kUsage = 2;

void usage()
{
    std::cerr << "usage: seed_db <database> [--force] [--pin-key <16 characters>]\n"
                 "  Creates a bank database filled with test accounts, cards, staff and ATMs.\n"
                 "  --force      replace the database if it already exists\n"
                 "  --pin-key    the bank HSM's PIN key (default: the demo key used by the app and the tests)\n";
}

void removeDatabase(const std::filesystem::path& path)
{
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(path.string() + "-wal", ignored);
    std::filesystem::remove(path.string() + "-shm", ignored);
}

std::string uahText(std::int64_t kop) { return std::to_string(kop / 100) + " UAH"; }

void printSummary(const std::string& path)
{
    std::cout << "Created " << path << " with TEST DATA ONLY\n\n";

    std::cout << "Cards\n";
    for (const DemoCard& card : demoCards())
    {
        std::cout << "  " << card.pan << "  PIN " << card.pin << "  exp " << (card.expMonth < 10 ? "0" : "") << card.expMonth << "/" << card.expYear << "  " << card.accountId << "  "
                  << uahText(card.balanceKop) << "  " << card.note << "\n";
    }

    std::cout << "\nStaff (password for all: " << kDemoStaffPassword << ")\n";
    for (const DemoStaff& staff : demoStaff()) std::cout << "  " << staff.id << "  " << roleToString(staff.role) << "\n";

    std::cout << "\nATMs\n";
    for (const std::string& atmId : demoAtms()) std::cout << "  " << atmId << "  cassettes: 50 notes each of 100, 200, 500, 1000\n";

    std::cout << "\nOnly the database is filled. The bank HSM still needs keys for these ATMs (BankHsm::provisionAtm).\n";
}
}

int main(int argc, char** argv)
{
    std::string path;
    std::string pinKey = kDemoPinKey;
    bool force = false;

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--force")
        {
            force = true;
        }
        else if (arg == "--pin-key" && i + 1 < argc)
        {
            pinKey = argv[++i];
        }
        else if (!arg.empty() && arg[0] != '-' && path.empty())
        {
            path = arg;
        }
        else
        {
            usage();
            return kUsage;
        }
    }
    if (path.empty() || pinKey.size() != 16)
    {
        usage();
        return kUsage;
    }

    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return kFailed;
    }

    std::error_code exists;
    if (std::filesystem::exists(path, exists))
    {
        if (!force)
        {
            std::cerr << path << " already exists; use --force to replace it\n";
            return kUsage;
        }
        removeDatabase(path);
    }

    try
    {
        {
            std::array<unsigned char, 32> signPublic{};
            std::array<unsigned char, 64> signSecret{};
            std::array<unsigned char, 32> boxPublic{};
            std::array<unsigned char, 32> boxSecret{};
            crypto_sign_keypair(signPublic.data(), signSecret.data());
            crypto_box_keypair(boxPublic.data(), boxSecret.data());
            auto serverKey = CryptoCore::randomBytes(16);
            if (!serverKey) throw std::runtime_error("no random bytes for the throwaway server key");

            BankHsm hsm(*serverKey, pinKey, signPublic, signSecret, boxPublic, boxSecret);
            Database db(path);
            seedDatabase(db, hsm);
        }
        printSummary(path);
        return kOk;
    }
    catch (const std::exception& e)
    {
        removeDatabase(path);
        std::cerr << "seed failed: " << e.what() << "\n";
        return kFailed;
    }
}

#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>

#include "audit/IAuditSigner.h"
#include "audit/LogStorage.h"
#include "audit/LogVerifier.h"
#include "server/db/Database.h"
#include "server/repo/CheckpointRepository.h"

namespace
{
class NoKeySigner final : public IAuditSigner
{
public:
    std::optional<std::string> sign(const std::string&) const override { return std::nullopt; }
    bool verify(const std::string&, const std::string&) const override { return false; }
};

int usage()
{
    std::cerr << "usage: verify_log <log-file> [--db <bank.db> --log-id <id>]\n";
    return 2;
}
}

int main(int argc, char** argv)
{
    if (argc != 2 && argc != 6) return usage();
    const std::string logPath = argv[1];
    std::string dbPath;
    std::string logId;
    if (argc == 6)
    {
        if (std::string(argv[2]) != "--db" || std::string(argv[4]) != "--log-id") return usage();
        dbPath = argv[3];
        logId = argv[5];
    }

    std::ifstream in(logPath, std::ios::binary);
    if (!in)
    {
        std::cerr << "error: cannot read " << logPath << "\n";
        return 2;
    }
    InMemoryLogStorage storage;
    for (std::string line; std::getline(in, line);) (void)storage.append(line);

    NoKeySigner signer;
    const LogVerifier verifier(storage, signer);
    bool intact = true;

    const VerifyResult chain = verifier.verifyChain();
    std::cout << "log: " << logPath << "\n";
    if (chain.ok)
        std::cout << "chain: ok, " << chain.entryCount << " entries\n";
    else
    {
        intact = false;
        std::cout << "chain: damaged from entry " << (chain.firstBadSeq ? std::to_string(*chain.firstBadSeq) : "?") << " (" << verifyErrorToString(chain.reason) << ")\n";
    }
    if (chain.recoveredTornEntries > 0) std::cout << "torn writes recorded: " << chain.recoveredTornEntries << "\n";

    if (!dbPath.empty())
    {
        try
        {
            Database db(dbPath, OpenMode::ReadOnly);
            const CheckpointRepository checkpoints(db);
            const auto latest = checkpoints.latest(logId);
            if (!latest)
                std::cout << "checkpoint: none stored for " << logId << "\n";
            else
            {
                const VerifyResult match = verifier.matchCheckpoint(*latest);
                if (match.ok)
                    std::cout << "checkpoint: entry " << latest->seqNo << " matches the stored checkpoint\n";
                else
                {
                    intact = false;
                    std::cout << "checkpoint: entry " << latest->seqNo << " " << verifyErrorToString(match.reason) << "\n";
                }
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "error: " << e.what() << "\n";
            return 2;
        }
    }

    std::cout << "open intents: " << verifier.openIntents().size() << "\n";
    return intact ? 0 : 1;
}

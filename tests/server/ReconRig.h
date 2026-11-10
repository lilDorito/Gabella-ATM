#pragma once
#include <map>
#include <set>
#include <string>

#include "ServerRig.h"
#include "server/db/Statement.h"
#include "server/repo/AccountRepository.h"
#include "server/repo/CassetteRepository.h"
#include "server/repo/TxRepository.h"
#include "server/services/ReconciliationService.h"

using Counts = std::map<int, int>;

inline const Counts kFull = { { 100, 50 }, { 200, 50 }, { 500, 50 }, { 1000, 50 } };

inline Counts counts(int c100, int c200, int c500, int c1000) { return { { 100, c100 }, { 200, c200 }, { 500, c500 }, { 1000, c1000 } }; }

struct FakeDecider final : IAccessDecider
{
    std::set<std::string> engineers;
    std::set<std::string> collectors;

    Decision decide(const AccessRequest& r) override
    {
        const bool allowed = r.atmId == kRigAtm && ((r.action == Action::LoadCash && engineers.count(r.staffToken) > 0) || (r.action == Action::CollectCash && collectors.count(r.staffToken) > 0));
        Decision d;
        d.verdict = allowed ? Verdict::Allowed : Verdict::Denied;
        d.reason = allowed ? DenyReason::None : DenyReason::NotPermitted;
        return d;
    }
};

struct ReconRig : ServerRig
{
    AccountRepository accounts{ db };
    TxRepository txs{ db };
    CassetteRepository cassettes{ db };
    FakeDecider decider;
    ReconciliationService recon{ db, txs, accounts, cassettes, decider, log, clock, config };
    BankServer reconServer{ *fx.bank, log, gate, atms, checkpointService, ServerParts{ unavailable, recon, unavailable, decider, unavailable } };

    ReconRig()
    {
        Statement account(db, "INSERT INTO accounts (account_id, owner_name, balance_kop) VALUES ('ACC-1', 'Owner', 1000000)");
        account.run();
        cassettes.replace(kRigAtm, kFull);
        decider.engineers.insert("tok-eng");
        decider.collectors.insert("tok-col");
    }

    std::int64_t hold(std::uint64_t seq, std::int64_t amountKop = 50000, std::int64_t ageSeconds = 0)
    {
        return txs.insertHeld(kRigAtm, "s-" + std::to_string(seq), "ACC-1", amountKop, seq, clock.nowUnix() - ageSeconds);
    }

    DispenseReport dispenseReport(std::uint64_t seq, DispenseResult result, const Counts& cassetteCounts)
    {
        DispenseReport r;
        r.atmId = kRigAtm;
        r.sessionId = "s-" + std::to_string(seq);
        r.sequence = seq;
        r.result = result;
        r.cassetteCounts = cassetteCounts;
        r.timestamp = clock.nowUnix();
        return r;
    }

    StatusReport statusReport(StatusReason reason, std::uint64_t lastSeq, const Counts& cassetteCounts, const std::string& token = "")
    {
        StatusReport r;
        r.atmId = kRigAtm;
        r.reason = reason;
        r.staffToken = token;
        r.lastExecutedSequence = lastSeq;
        r.cassetteCounts = cassetteCounts;
        r.timestamp = clock.nowUnix();
        return r;
    }

    TxStatus status(std::uint64_t seq) { return txs.findBySeq(kRigAtm, seq)->status; }

    std::int64_t balance() { return *accounts.balance("ACC-1"); }

    Counts expected() { return cassettes.expected(kRigAtm); }

    std::size_t events(EventType type, Outcome outcome)
    {
        std::size_t n = 0;
        for (const auto& entry : LogVerifier(logStorage, logSigner).readEntries(1, 1000000))
        {
            if (entry.getEvent().type == type && entry.getEvent().outcome == outcome) ++n;
        }
        return n;
    }
};

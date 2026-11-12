#pragma once
// Fixture for the staff / access / command tests: an in-memory SQLite database with the real schema,
// the real repositories and services, a real BankHsm (libsodium keys) and a controllable log.
// It has the same shape as ServerRig.h; if ServerRig already builds Database, Clock, log and BankHsm,
// move the members below "services" into it and drop the duplicates.
#include <sodium.h>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include "access/AccessControl.h"
#include "access/ApprovalPolicy.h"
#include "access/DualControlManager.h"
#include "access/PermissionTable.h"
#include "access/SessionRegistry.h"
#include "access/StaffTokenStore.h"
#include "audit/IAuditSink.h"
#include "common/Clock.h"
#include "crypto/BankHsm.h"
#include "crypto/CryptoCore.h"
#include "server/AdminConsole.h"
#include "server/SystemConfig.h"
#include "server/db/Database.h"
#include "server/repo/AtmRepository.h"
#include "server/repo/CommandRepository.h"
#include "server/repo/DualControlRepository.h"
#include "server/repo/StaffRepository.h"
#include "server/services/AccessDecider.h"
#include "server/services/CommandService.h"
#include "server/services/StaffAuthenticator.h"
#include "server/services/StaffService.h"

namespace server_test
{

inline const std::string kAtmA = "ATM-001";
inline const std::string kAtmB = "ATM-002";
inline const std::string kPassword = "S3cretPass";
inline const std::int64_t kStart = 1792000000;

// The log the tests look into. It can be switched off, and it refuses what DataPolicy refuses:
// a run of 13 or more digits in details or in the actor id.
class TestLog final : public IAuditSink
{
private:
    static bool longDigitRun(const std::string& text)
    {
        std::size_t run = 0;
        for (char c : text)
        {
            run = (c >= '0' && c <= '9') ? run + 1 : 0;
            if (run >= 13) return true;
        }
        return false;
    }

public:
    std::vector<LogEvent> events;
    bool down = false;

    bool record(const LogEvent& e) override
    {
        if (down || longDigitRun(e.details) || longDigitRun(e.actorId)) return false;
        events.push_back(e);
        return true;
    }

    std::size_t count(EventType type) const
    {
        std::size_t n = 0;
        for (const LogEvent& e : events) n += e.type == type ? 1 : 0;
        return n;
    }

    bool has(EventType type, Outcome outcome, const std::string& needle = "") const
    {
        for (const LogEvent& e : events)
            if (e.type == type && e.outcome == outcome && e.details.find(needle) != std::string::npos) return true;
        return false;
    }

    // Index of the first / last event with this opId and outcome, or -1.
    int indexOf(const std::string& opId, Outcome outcome) const
    {
        for (std::size_t i = 0; i < events.size(); ++i)
            if (events[i].opId == opId && events[i].outcome == outcome) return static_cast<int>(i);
        return -1;
    }

    // Every opId that has an Info intent must have a closing event after it.
    bool everyIntentIsClosed() const
    {
        for (std::size_t i = 0; i < events.size(); ++i)
        {
            if (events[i].opId.empty() || events[i].outcome != Outcome::Info) continue;
            bool closed = false;
            for (std::size_t j = i + 1; j < events.size(); ++j)
                closed = closed || (events[j].opId == events[i].opId && events[j].outcome != Outcome::Info);
            if (!closed) return false;
        }
        return true;
    }

    bool anyDetailContains(const std::string& needle) const
    {
        for (const LogEvent& e : events)
            if (e.details.find(needle) != std::string::npos || e.actorId.find(needle) != std::string::npos) return true;
        return false;
    }
};

// Test-only stand-in for argon2id: the "hash" is the password behind a marker.
inline std::string fakeHash(const std::string& password) { return "$argon2id$fake$" + password; }

inline PasswordCheckFn fakeCheck()
{
    return [](const std::string& hash, const std::string& password) { return hash == fakeHash(password); };
}

inline std::unique_ptr<BankHsm> makeBankHsm()
{
    if (sodium_init() < 0) throw std::runtime_error("libsodium cannot be initialised");
    std::array<unsigned char, 32> signPublic{};
    std::array<unsigned char, 64> signSecret{};
    std::array<unsigned char, 32> boxPublic{};
    std::array<unsigned char, 32> boxSecret{};
    crypto_sign_keypair(signPublic.data(), signSecret.data());
    crypto_box_keypair(boxPublic.data(), boxSecret.data());
    const auto key = [] { return *CryptoCore::randomBytes(16); };
    return std::make_unique<BankHsm>(key(), key(), key(), key(), key(), signPublic, signSecret, boxPublic, boxSecret);
}

struct StaffRig
{
    Database db{ ":memory:" };
    FakeClock clock{ kStart };
    TestLog log;
    SystemConfig config;
    std::unique_ptr<BankHsm> hsm = makeBankHsm();

    AtmRepository atms{ db };
    StaffRepository staff{ db };
    DualControlRepository requests{ db };
    CommandRepository commandQueue{ db };

    PermissionTable permissions = PermissionTable::makeDefault();
    ApprovalPolicy policy = ApprovalPolicy::makeDefault();
    SessionRegistry sessions{ clock };
    StaffTokenStore tokens{ clock, [](std::size_t n) { return CryptoCore::randomBytes(n); }, config.staffTokenIdleSeconds, config.staffTokenMaxSeconds };
    DualControlManager dual{ requests, policy, clock, log, [](std::size_t n) { return CryptoCore::randomBytes(n); }, [this] { return staff.countActiveAdmins(); } };
    SqliteStaffAuthenticator authenticator{ staff, log, clock, config, fakeCheck(), fakeHash("dummy-password-nobody-has") };
    AccessControl access{ permissions, dual, sessions, tokens, authenticator, log };

    StaffService staffService{ *hsm, access, log };
    AccessDecider decider{ access, policy, atms, log };
    CommandService commands{ *hsm, db, atms, commandQueue, dual, requests, log, clock, config };
    AdminConsole console{ access, tokens, dual, commands, atms, log };

    StaffRig()
    {
        atms.insert(kAtmA);
        atms.insert(kAtmB);
        addStaff("A-01", Role::Admin);
        addStaff("A-02", Role::Admin);
        addStaff("A-03", Role::Admin);
        addStaff("E-01", Role::ServiceEngineer);
        addStaff("AU-01", Role::Auditor);
    }

    void addStaff(const std::string& id, Role role, const std::string& password = kPassword)
    {
        StaffRecord s;
        s.staffId = id;
        s.role = role;
        s.passwordHash = fakeHash(password);
        staff.insert(s);
    }

    std::string seal(const std::string& password) const
    {
        const auto pk = hsm->boxPublicKey();
        std::string sealed(password.size() + crypto_box_SEALBYTES, '\0');
        crypto_box_seal(reinterpret_cast<unsigned char*>(&sealed[0]), reinterpret_cast<const unsigned char*>(password.data()), password.size(), pk.data());
        return sealed;
    }

    StaffLoginRequest loginRequest(const std::string& staffId, const std::string& password, const std::string& atmId = kAtmA) const
    {
        StaffLoginRequest r;
        r.atmId = atmId;
        r.staffId = staffId;
        r.sealedPassword = seal(password);
        r.nonce = "n";
        r.timestamp = clock.nowUnix();
        return r;
    }

    std::optional<StaffLoginResult> login(const std::string& staffId, const std::string& password = kPassword, const std::string& atmId = kAtmA)
    {
        return staffService.staffLogin(loginRequest(staffId, password, atmId));
    }

    std::string consoleToken(const std::string& staffId)
    {
        const auto r = console.login(staffId, kPassword);
        return r ? r->token : std::string();
    }

    // Opens a request from the console and approves it with the first `approvers` admins.
    std::string approvedRequest(Action action, const std::string& atmId, const std::string& extra, int approvers = 2)
    {
        const std::string first = consoleToken("A-01");
        const Decision d = console.createRequest(first, action, atmId, extra);
        if (d.verdict != Verdict::PendingApproval) return std::string();
        for (int i = 1; i < approvers; ++i)
            (void)console.approve(consoleToken(i == 1 ? "A-02" : "A-03"), d.requestId);
        return d.requestId;
    }

    // Verifies the signature the way an ATM does: with the bank's public key and the Command domain tag.
    bool commandSignatureValid(const SignedCommand& c) const
    {
        const auto pk = hsm->signPublicKey();
        const std::string tagged = std::string(tagOf(SignDomain::Command)) + c.signedPayload();
        return c.signature.size() == crypto_sign_BYTES
            && crypto_sign_verify_detached(reinterpret_cast<const unsigned char*>(c.signature.data()), reinterpret_cast<const unsigned char*>(tagged.data()), tagged.size(), pk.data()) == 0;
    }
};

}

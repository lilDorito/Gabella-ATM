#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "Check.h"
#include "StaffRig.h"

#include "server/db/DbError.h"
#include "server/db/Statement.h"
#include "server/services/CommandParams.h"
#include "server/services/PasswordVerifier.h"

using gabella_test::check;
using gabella_test::section;
using namespace server_test;

namespace
{

bool sqlRefuses(Database& db, const char* sql)
{
    try
    {
        db.exec(sql);
    }
    catch (const DbError&)
    {
        return true;
    }
    return false;
}

void staffRepositoryTests()
{
    section("StaffRepository");
    StaffRig r;

    const auto admin = r.staff.find("A-01");
    check(admin && admin->role == Role::Admin && admin->active && admin->failedLogins == 0, "a stored staff member is read back");
    check(!r.staff.find("nobody"), "an unknown id is not found");
    check(r.staff.countActiveAdmins() == 3, "three active admins are counted");

    r.addStaff("A-04", Role::Admin);
    StaffRecord off;
    off.staffId = "A-05";
    off.role = Role::Admin;
    off.passwordHash = fakeHash("x");
    off.active = false;
    r.staff.insert(off);
    check(r.staff.countActiveAdmins() == 4, "a disabled admin is not counted");

    StaffRecord bad;
    bad.staffId = "X-01";
    bad.role = Role::System;
    bad.passwordHash = fakeHash("x");
    bool threw = false;
    try
    {
        r.staff.insert(bad);
    }
    catch (const DbError&)
    {
        threw = true;
    }
    check(threw, "the System role cannot be stored as staff");

    bool plain = false;
    StaffRecord weak;
    weak.staffId = "X-02";
    weak.role = Role::Auditor;
    weak.passwordHash = "plaintext";
    try
    {
        r.staff.insert(weak);
    }
    catch (const DbError&)
    {
        plain = true;
    }
    check(plain, "the schema refuses a password hash that is not argon2id");

    const std::int64_t now = kStart;
    LoginFailure f;
    for (int i = 1; i <= 4; ++i)
    {
        f = r.staff.recordFailure("E-01", now, 5, 900);
        check(f.attempts == static_cast<std::uint32_t>(i) && !f.locked, "failure " + std::to_string(i) + " is counted without a lock");
    }
    f = r.staff.recordFailure("E-01", now, 5, 900);
    check(f.attempts == 5 && f.locked && f.lockedUntil == now + 900, "the fifth failure locks for 15 minutes");

    r.staff.resetFailures("E-01");
    const auto cleared = r.staff.find("E-01");
    check(cleared && cleared->failedLogins == 0 && cleared->lockedUntil == 0, "reset clears the counter and the lock");

    for (int i = 0; i < 5; ++i) (void)r.staff.recordFailure("AU-01", now, 5, 900);
    const auto again = r.staff.recordFailure("AU-01", now + 901, 5, 900);
    check(again.attempts == 1 && !again.locked, "a failure after the lock expired starts counting from one");
}

void loginTests()
{
    section("StaffService login");
    {
        StaffRig r;
        const auto ok = r.login("E-01");
        check(ok && ok->role == Role::ServiceEngineer && !ok->token.empty(), "correct password gives a token and the role");
        check(r.log.has(EventType::STAFF_LOGIN, Outcome::Success), "the successful login is logged");
        check(!r.log.anyDetailContains(kPassword), "the password is never written to the log");
    }
    {
        StaffRig r;
        check(!r.login("E-01", "wrong"), "wrong password gives no token");
        const auto s = r.staff.find("E-01");
        check(s && s->failedLogins == 1, "the failure is stored in the database");
        check(r.log.everyIntentIsClosed(), "the failure counter change is logged as intent and result");
    }
    {
        StaffRig r;
        check(!r.login("ghost"), "unknown id gives no token");
        check(r.log.has(EventType::STAFF_LOGIN, Outcome::Failure, "unknown_staff"), "unknown id is logged");
    }
    {
        StaffRig r;
        StaffLoginRequest req = r.loginRequest("E-01", kPassword);
        req.sealedPassword = "not a sealed box";
        check(!r.staffService.staffLogin(req), "a password that cannot be opened is refused");
        const auto s = r.staff.find("E-01");
        check(s && s->failedLogins == 0, "an unopenable password does not count as a wrong password");
    }
    {
        StaffRig r;
        check(!r.login("E-01", kPassword, kAdminConsoleAtmId), "an ATM cannot log in as the admin console");
        check(!r.login("E-01", std::string(200, 'x')), "an oversized password is refused");
    }
    {
        StaffRig r;
        StaffRecord off;
        off.staffId = "E-09";
        off.role = Role::ServiceEngineer;
        off.passwordHash = fakeHash(kPassword);
        off.active = false;
        r.staff.insert(off);
        check(!r.login("E-09"), "a disabled account cannot log in with the right password");
    }
    {
        StaffRig r;
        r.log.down = true;
        check(!r.login("E-01"), "no token while the log is unavailable");
        r.log.down = false;
        check(r.tokens.activeCount() == 0, "no token was left behind");
    }
    {
        StaffRig r;
        check(!r.login("1234567890123456"), "a hostile id made of digits gives no token");
        check(r.log.has(EventType::STAFF_LOGIN, Outcome::Failure, "actor_id=withheld"), "the log keeps the event without the hostile id");
    }
}

void lockoutTests()
{
    section("Lockout: 5 failures, 15 minutes");
    StaffRig r;
    for (int i = 0; i < 4; ++i) (void)r.login("E-01", "wrong");
    check(r.login("E-01").has_value(), "the correct password still works after four failures");
    const auto afterOk = r.staff.find("E-01");
    check(afterOk && afterOk->failedLogins == 0, "a success clears the failure counter");

    for (int i = 0; i < 5; ++i) (void)r.login("E-01", "wrong");
    const auto locked = r.staff.find("E-01");
    check(locked && locked->lockedUntil == kStart + 900, "five failures set the lock");
    check(r.log.count(EventType::STAFF_LOCKED) == 1, "the lock is logged once");
    check(r.log.has(EventType::STAFF_LOCKED, Outcome::Failure, "locked_until=" + std::to_string(kStart + 900)), "the lock log says until when");

    check(!r.login("E-01"), "the correct password is refused during the lock");
    r.clock.advance(899);
    check(!r.login("E-01"), "still locked one second before the end");
    const auto stillLocked = r.staff.find("E-01");
    check(stillLocked && stillLocked->lockedUntil == kStart + 900, "attempts during the lock do not move it");

    r.clock.advance(1);
    check(r.login("E-01").has_value(), "the correct password works when the lock has run out");
    const auto freed = r.staff.find("E-01");
    check(freed && freed->failedLogins == 0 && freed->lockedUntil == 0, "the lock and the counter are cleared");
    check(r.log.everyIntentIsClosed(), "every counter change has a result in the log");

    StaffRig again;
    for (int i = 0; i < 5; ++i) (void)again.login("AU-01", "wrong");
    again.clock.advance(901);
    (void)again.login("AU-01", "wrong");
    const auto restarted = again.staff.find("AU-01");
    check(restarted && restarted->failedLogins == 1 && restarted->lockedUntil == 0, "after a finished lock the count starts again, one failure does not re-lock");
}

void logoutAndTokenTests()
{
    section("Logout and tokens");
    StaffRig r;
    const auto in = r.login("E-01");
    AccessRequest req;
    req.atmId = kAtmA;
    req.staffToken = in->token;
    req.action = Action::RunDiagnostics;
    check(r.decider.decide(req).verdict == Verdict::Allowed, "a logged-in engineer may run diagnostics");
    r.staffService.staffLogout(in->token);
    const Decision after = r.decider.decide(req);
    check(after.verdict == Verdict::Denied && after.reason == DenyReason::NotLoggedIn, "after logout the token is dead");

    const auto idle = r.login("E-01");
    req.staffToken = idle->token;
    r.clock.advance(r.config.staffTokenIdleSeconds + 1);
    check(r.decider.decide(req).reason == DenyReason::NotLoggedIn, "an idle token expires");
}

void accessDeciderTests()
{
    section("AccessDecider");
    StaffRig r;
    const auto engineer = r.login("E-01");
    const auto auditor = r.login("AU-01");

    AccessRequest req;
    req.atmId = kAtmA;
    req.staffToken = engineer->token;
    req.action = Action::LoadCash;
    check(r.decider.decide(req).verdict == Verdict::Allowed, "the engineer may load cash on his own ATM");

    req.atmId = kAtmB;
    const Decision other = r.decider.decide(req);
    check(other.verdict == Verdict::Denied && other.reason == DenyReason::NotLoggedIn, "the token is not valid on another ATM");

    req.atmId = kAtmA;
    req.action = Action::CollectCash;
    const Decision wrongRole = r.decider.decide(req);
    check(wrongRole.verdict == Verdict::Denied && wrongRole.reason == DenyReason::NotPermitted, "the engineer may not collect cash");
    check(r.log.has(EventType::ACCESS_DENIED, Outcome::Failure, "action=CollectCash"), "the refusal is logged");

    req.staffToken = auditor->token;
    req.action = Action::ReadLog;
    check(r.decider.decide(req).verdict == Verdict::Allowed, "the auditor may read the log");

    req.atmId = "ATM-404";
    check(r.decider.decide(req).verdict == Verdict::Denied, "an unknown ATM gets nothing");

    req.atmId = kAtmA;
    req.staffToken = "forged-token";
    check(r.decider.decide(req).reason == DenyReason::NotLoggedIn, "a forged token is refused");

    req.staffToken.clear();
    req.sessionId = "no-such-session";
    check(r.decider.decide(req).reason == DenyReason::NoSession, "a client without an open session is refused");

    check(r.atms.setStatus(kAtmA, AtmStatus::OutOfService), "the ATM is put out of service");
    req.staffToken = auditor->token;
    req.sessionId.clear();
    const Decision oos = r.decider.decide(req);
    check(oos.verdict == Verdict::Denied && oos.reason == DenyReason::AtmOutOfService, "an out-of-service ATM is refused");
    check(r.atms.setStatus(kAtmA, AtmStatus::Active), "the ATM is back in service");

    check(!r.login("A-01"), "an admin cannot sign in at an ATM");
    const std::string adminToken = r.tokens.issue("A-01", Role::Admin, kAtmA);
    AccessRequest critical;
    critical.atmId = kAtmA;
    critical.staffToken = adminToken;
    critical.action = Action::UpdateWorkingKey;
    critical.params = "Mac";
    const Decision pending = r.decider.decide(critical);
    check(pending.verdict == Verdict::PendingApproval && !pending.requestId.empty(), "a critical action waits for approval");
    const auto stored = r.requests.find(pending.requestId);
    check(stored && stored->params == "atm=ATM-001|Mac" && stored->status == RequestStatus::Pending, "the request is stored in the database, bound to the asking ATM");

    critical.params = "atm=ATM-002|Mac";
    const Decision spoof = r.decider.decide(critical);
    const auto spoofed = r.requests.find(spoof.requestId);
    const auto target = spoofed ? parseCommandParams(spoofed->params) : std::nullopt;
    check(target && target->atmId == kAtmA, "params from the ATM cannot name another ATM");
}

void dualControlRepositoryTests()
{
    section("Dual control in SQLite");
    {
        StaffRig r;
        const std::string id = r.approvedRequest(Action::RestoreFromOutOfService, kAtmA, "", 1);
        check(!id.empty(), "a request is opened from the console");
        const auto req = r.requests.find(id);
        check(req && req->status == RequestStatus::Pending && req->approvers.size() == 1 && req->approvers[0] == "A-01", "the initiator is the first approval row");
        check(req && req->requiredApprovals == 2, "the threshold for three admins is 2 and is stored");
        check(r.requests.countApprovals(id) == 1, "approvals are counted from the table");

        const auto admin2 = r.consoleToken("A-02");
        check(r.console.approve(r.consoleToken("A-01"), id).result == ApprovalResult::AlreadyApproved, "the same admin cannot approve twice");
        check(r.console.approve(admin2, id).result == ApprovalResult::Approved, "the second admin completes the request");
        check(r.requests.find(id)->status == RequestStatus::Approved, "status is stored as APPROVED");
        check(r.log.count(EventType::DUAL_CONTROL_REQUESTED) == 1 && r.log.count(EventType::DUAL_CONTROL_APPROVED) >= 1, "request and approval are logged");
    }
    {
        StaffRig r;
        const std::string id = r.approvedRequest(Action::RestoreFromOutOfService, kAtmA, "", 1);
        check(sqlRefuses(r.db, ("UPDATE dual_control_requests SET status = 'EXECUTED' WHERE request_id = '" + id + "'").c_str()), "the database refuses PENDING -> EXECUTED");
        check(sqlRefuses(r.db, ("UPDATE dual_control_requests SET params = 'atm=ATM-002' WHERE request_id = '" + id + "'").c_str()), "the database refuses changed params");
        check(sqlRefuses(r.db, ("UPDATE dual_control_requests SET required_approvals = 2 WHERE request_id = '" + id + "'").c_str()), "the database refuses a changed threshold");
    }
    {
        StaffRig r;
        const std::string id = r.approvedRequest(Action::RestoreFromOutOfService, kAtmA, "", 1);
        r.clock.advance(r.policy.ttlSeconds);
        check(r.console.approve(r.consoleToken("A-02"), id).result == ApprovalResult::Expired, "a request older than 30 minutes cannot be approved");
        check(r.requests.find(id)->status == RequestStatus::Expired, "the expiry is stored");
    }
    {
        StaffRig r;
        CriticalRequest req;
        req.requestId = "DC-test-0000-0000-0001";
        req.action = Action::ResolveTransaction;
        req.params = "atm=ATM-001|tx=5";
        req.initiatorId = "A-01";
        req.createdAt = kStart;
        req.expiresAt = kStart + 1800;
        const bool rolledBack = !r.requests.inTransaction([&] { return r.requests.insertRequest(req) && false; });
        check(rolledBack && !r.requests.find(req.requestId), "a transaction that returns false leaves nothing behind");
        const bool thrown = !r.requests.inTransaction(
            [&]() -> bool
            {
                (void)r.requests.insertRequest(req);
                throw std::runtime_error("boom");
            });
        check(thrown && !r.requests.find(req.requestId), "a transaction that throws is rolled back");
        check(r.requests.inTransaction([&] { return r.requests.insertRequest(req) && r.requests.insertApproval(req.requestId, "A-01", kStart); }), "a good transaction commits");
        check(!r.requests.insertRequest(req), "the same request id cannot be inserted twice");
        check(r.requests.inTransaction([&] { return r.requests.inTransaction([&] { return r.requests.insertApproval(req.requestId, "A-02", kStart); }); }), "a nested call joins the open transaction");
    }
    {
        const std::filesystem::path path = std::filesystem::temp_directory_path() / "gabella_staff_access_test.db";
        std::filesystem::remove(path);
        std::string id;
        {
            Database db(path.string());
            AtmRepository atms(db);
            atms.insert(kAtmA);
            DualControlRepository requests(db);
            CriticalRequest req;
            req.requestId = "DC-keep-0000-0000-0001";
            req.action = Action::UpdateWorkingKey;
            req.params = "atm=ATM-001|Mac";
            req.initiatorId = "A-01";
            req.requiredApprovals = 2;
            req.createdAt = kStart;
            req.expiresAt = kStart + 1800;
            id = req.requestId;
            check(requests.insertRequest(req) && requests.insertApproval(id, "A-01", kStart), "a request is written to a database file");
        }
        {
            Database db(path.string());
            DualControlRepository requests(db);
            const auto back = requests.find(id);
            check(back && back->action == Action::UpdateWorkingKey && back->approvers.size() == 1 && back->params == "atm=ATM-001|Mac", "the request and its approval survive a restart");
            check(requests.listPending().size() == 1, "the pending list is read from the table");
        }
        std::filesystem::remove(path);
        std::filesystem::remove(path.string() + "-wal");
        std::filesystem::remove(path.string() + "-shm");
    }
}

void commandTests()
{
    section("CommandService: RestoreFromOutOfService");
    {
        StaffRig r;
        check(r.atms.setStatus(kAtmA, AtmStatus::OutOfService), "the ATM is out of service");
        const std::string id = r.approvedRequest(Action::RestoreFromOutOfService, kAtmA, "");
        check(!id.empty() && r.requests.find(id)->status == RequestStatus::Approved, "two admins approved the request");

        const auto commands = r.commands.pollCommands(kAtmA);
        check(commands.size() == 1 && commands[0].action == Action::RestoreFromOutOfService && commands[0].commandSeq == 1, "an approved request becomes command 1 for the ATM");
        check(!commands.empty() && r.commandSignatureValid(commands[0]), "the command carries the bank's Command signature");
        check(r.commands.pollCommands(kAtmB).empty(), "another ATM sees nothing");
        check(r.atms.find(kAtmA)->lastCommandSeq == 1, "the sequence counter of the ATM moved");
        check(r.commands.enqueueApproved(id) == EnqueueResult::AlreadyQueued, "queueing the same request again does nothing");
        check(r.commands.pollCommands(kAtmA).size() == 1, "there is still one command");

        check(r.log.indexOf(CommandService::enqueueOpId(id), Outcome::Info) >= 0
                && r.log.indexOf(CommandService::enqueueOpId(id), Outcome::Info) < r.log.indexOf(CommandService::enqueueOpId(id), Outcome::Success),
            "the queueing intent is logged before its result");

        check(r.commands.reportCommandResult(kAtmA, 1, true), "the ATM reports success");
        check(r.atms.find(kAtmA)->status == AtmStatus::Active, "the ATM is Active again");
        check(r.requests.find(id)->status == RequestStatus::Executed, "the request is Executed");
        check(r.commands.pollCommands(kAtmA).empty(), "a finished command is not offered again");
        check(!r.commands.reportCommandResult(kAtmA, 1, true), "a repeated result is refused");
        check(!r.commands.reportCommandResult(kAtmA, 99, true), "a result for an unknown command is refused");
        check(!r.commands.reportCommandResult(kAtmB, 1, true), "another ATM cannot report this command");
        check(r.log.indexOf(CommandService::resultOpId(kAtmA, 1), Outcome::Info) < r.log.indexOf(CommandService::resultOpId(kAtmA, 1), Outcome::Success)
                && r.log.indexOf(CommandService::resultOpId(kAtmA, 1), Outcome::Success) > 0,
            "the result intent is logged before the change and closed after it");
        check(r.log.everyIntentIsClosed(), "every intent has a result");
    }
    {
        StaffRig r;
        check(r.atms.setStatus(kAtmA, AtmStatus::OutOfService), "the ATM is out of service");
        const std::string id = r.approvedRequest(Action::RestoreFromOutOfService, kAtmA, "");
        check(r.commands.reportCommandResult(kAtmA, 1, false), "a failed execution is accepted as a report");
        check(r.atms.find(kAtmA)->status == AtmStatus::OutOfService, "the ATM stays out of service");
        check(r.requests.find(id)->status == RequestStatus::Approved, "the request is not marked Executed");
        check(r.commandQueue.find(kAtmA, 1)->status == CommandStatus::Failed, "the command is stored as FAILED");
        check(r.log.has(EventType::DUAL_CONTROL_EXECUTED, Outcome::Failure, "ok=0"), "the failure is logged");
        check(r.commands.enqueueApproved(id) == EnqueueResult::AlreadyQueued, "a failed command is not queued again by itself");
    }
    {
        StaffRig r;
        check(r.atms.setStatus(kAtmA, AtmStatus::OutOfService), "the ATM is out of service");
        const std::string id = r.approvedRequest(Action::RestoreFromOutOfService, kAtmA, "");
        r.log.down = true;
        check(!r.commands.reportCommandResult(kAtmA, 1, true), "no result is accepted while the log is down");
        r.log.down = false;
        check(r.atms.find(kAtmA)->status == AtmStatus::OutOfService && r.commandQueue.find(kAtmA, 1)->status == CommandStatus::Queued, "nothing was changed without an intent in the log");
        check(r.requests.find(id)->status == RequestStatus::Approved, "the request is untouched");
    }
    {
        StaffRig r;
        const std::string first = r.consoleToken("A-01");
        const Decision d = r.console.createRequest(first, Action::RestoreFromOutOfService, kAtmA);
        r.log.down = true;
        const ApprovalResult res = r.approvals.approve(d.requestId, r.consoleToken("A-02"));
        r.log.down = false;
        check(res != ApprovalResult::Approved, "no approval is stored while the log is down");
        check(r.commands.enqueueApproved(d.requestId) == EnqueueResult::NotApproved, "a pending request cannot be queued");
    }
    {
        StaffRig r;
        const std::string first = r.consoleToken("A-01");
        const Decision d = r.console.createRequest(first, Action::RestoreFromOutOfService, kAtmA);
        check(r.approvals.approve(d.requestId, r.consoleToken("A-02")) == ApprovalResult::Approved, "approved without going through the console");
        check(r.commands.pollCommands(kAtmA).empty(), "so no command exists yet (a crash between approval and queueing)");
        check(r.commands.tick() == 1 && r.commands.pollCommands(kAtmA).size() == 1, "tick queues the forgotten approval");
        check(r.commands.tick() == 0, "and does it only once");
    }
    {
        StaffRig r;
        const std::string id = r.approvedRequest(Action::ResolveTransaction, kAtmA, "tx=5");
        check(!id.empty() && r.requests.find(id)->status == RequestStatus::Approved, "a ResolveTransaction request can be approved");
        check(r.commands.enqueueApproved(id) == EnqueueResult::NotACommand && r.commands.pollCommands(kAtmA).empty(), "but it is not an ATM command");
    }

    section("CommandService: UpdateWorkingKey");
    {
        StaffRig r;
        const std::string id = r.approvedRequest(Action::UpdateWorkingKey, kAtmA, "Mac");
        const auto commands = r.commands.pollCommands(kAtmA);
        check(commands.size() == 1 && commands[0].action == Action::UpdateWorkingKey, "the key update is queued");
        check(!commands.empty() && commands[0].params.rfind("Mac|", 0) == 0 && commands[0].params.size() > 4, "its params are <type>|<blob>");
        check(!commands.empty() && r.commandSignatureValid(commands[0]), "the blob is covered by the signature");
        check(!r.log.anyDetailContains(commands[0].params.substr(4)), "the key blob is not written to the log");

        const std::string second = r.approvedRequest(Action::UpdateWorkingKey, kAtmA, "Mac");
        check(!second.empty() && r.commandQueue.findByRequest(second) == std::nullopt, "a second Mac update for the same ATM cannot start while the first is pending");
        check(r.commands.enqueueApproved(second) == EnqueueResult::KeyUnavailable, "the refusal says the key is unavailable");

        check(r.commands.reportCommandResult(kAtmA, 1, true), "the ATM confirms the new key");
        check(r.requests.find(id)->status == RequestStatus::Executed, "the request is Executed");
        check(!r.hsm->commitWorkingKey(kAtmA, KeyType::Mac), "the bank has already switched: nothing is left pending");
        check(r.log.count(EventType::KEY_UPDATED) == 1, "the key switch is logged");
    }
    {
        StaffRig r;
        const std::string id = r.approvedRequest(Action::UpdateWorkingKey, kAtmA, "Audit");
        check(r.commands.pollCommands(kAtmA).size() == 1, "an Audit key update is queued");
        check(r.commands.reportCommandResult(kAtmA, 1, false), "the ATM reports that it failed");
        check(!r.hsm->commitWorkingKey(kAtmA, KeyType::Audit), "the pending key was dropped, the bank keeps the old one");
        check(r.requests.find(id)->status == RequestStatus::Approved, "the request stays Approved");
        check(r.hsm->prepareWorkingKey(kAtmA, KeyType::Audit).has_value(), "a new attempt can start");
    }
    {
        StaffRig r;
        const std::string id = r.approvedRequest(Action::UpdateWorkingKey, kAtmA, "Mac");
        check(r.commands.pollCommands(kAtmA).size() == 1, "queued");
        r.clock.advance(r.config.dualControlTtlSeconds);
        check(r.commands.pollCommands(kAtmA).empty(), "an expired command is not offered to the ATM");
        check(r.commands.tick() >= 1, "tick closes the expired command");
        check(r.commandQueue.find(kAtmA, 1)->status == CommandStatus::Failed, "it is stored as FAILED");
        check(r.hsm->prepareWorkingKey(kAtmA, KeyType::Mac).has_value(), "its pending key was dropped");
        check(r.requests.find(id)->status != RequestStatus::Executed, "an expired command never executes the request");
        check(r.log.everyIntentIsClosed(), "the expiry is logged as intent and result");
    }
    {
        StaffRig r;
        const std::string spoofed = r.approvedRequest(Action::UpdateWorkingKey, kAtmA, "NotAKey");
        check(r.commands.enqueueApproved(spoofed) == EnqueueResult::BadParams, "an unknown key type is refused");
        check(r.commands.pollCommands(kAtmA).empty(), "nothing is queued for it");
    }
    {
        StaffRig r;
        const std::string id = r.approvedRequest(Action::RestoreFromOutOfService, kAtmA, "");
        const auto queued = r.commandQueue.findByRequest(id);
        check(queued && queued->signature.size() == 64 && queued->requestId == id, "the stored command refers to its request");
    }
}

void consoleTests()
{
    section("AdminConsole");
    StaffRig r;
    check(!r.console.login("E-01", kPassword), "a service engineer cannot use the console");
    check(r.tokens.activeCount() == 0, "and his token is not left alive");
    check(!r.console.login("A-01", "wrong"), "a wrong admin password is refused");

    const std::string token = r.consoleToken("A-01");
    check(!token.empty(), "an admin logs in");

    const auto atmToken = r.login("A-02", kPassword, kAtmA);
    check(r.console.atms(atmToken->token).empty(), "an admin token from an ATM does not open the console");
    check(r.console.createRequest(atmToken->token, Action::RestoreFromOutOfService, kAtmA).verdict == Verdict::Denied, "nor does it create requests");
    check(r.console.approve(atmToken->token, "DC-ffff-ffff-ffff-ffff").result == ApprovalResult::NotEligible, "nor approve");

    check(r.atms.flagLogReview(kAtmB), "ATM-002 is flagged for a log review");
    check(r.atms.setStatus(kAtmB, AtmStatus::OutOfService), "and is out of service");
    const auto list = r.console.atms(token);
    check(list.size() == 2, "the console lists both ATMs");
    check(list.size() == 2 && AdminConsole::formatAtm(list[0]).find("CHECK THE LOG") == std::string::npos, "a clean ATM has no flag");
    check(list.size() == 2 && AdminConsole::formatAtm(list[1]).find("CHECK THE LOG") != std::string::npos && AdminConsole::formatAtm(list[1]).find("OUT_OF_SERVICE") != std::string::npos,
        "the flagged ATM shows CHECK THE LOG");

    check(r.console.createRequest(token, Action::RestoreFromOutOfService, "ATM-404").verdict == Verdict::Denied, "a request for an unknown ATM is refused");
    check(r.console.createRequest(token, Action::RestoreFromOutOfService, "A|B").verdict == Verdict::Denied, "a malformed ATM id is refused");
    const Decision d = r.console.createRequest(token, Action::RestoreFromOutOfService, kAtmB);
    check(d.verdict == Verdict::PendingApproval, "an admin opens a request");

    const auto pending = r.console.pending(token);
    check(pending.size() == 1 && pending[0].atmId == kAtmB && pending[0].approvals == 1, "the pending list shows the target and the approvals");
    check(pending.size() == 1 && AdminConsole::formatPending(pending[0]).find("approvals=1/2") != std::string::npos, "and how many are still needed");

    const ConsoleApproval second = r.console.approve(r.consoleToken("A-02"), d.requestId);
    check(second.result == ApprovalResult::Approved && second.queued && *second.queued == EnqueueResult::Queued, "the second approval queues the command");
    check(r.console.pending(token).empty(), "the request leaves the pending list");

    r.console.logout(token);
    check(r.console.atms(token).empty(), "after logout the console token is dead");

    StaffRig scripted;
    std::istringstream in("help\nlogin A-01 S3cretPass\natms\nrequest RestoreFromOutOfService ATM-001\npending\nlogout\nquit\n");
    std::ostringstream out;
    check(scripted.console.run(in, out) == 0, "the console loop ends cleanly");
    check(out.str().find("ATM-001") != std::string::npos && out.str().find("waiting for approvals") != std::string::npos && out.str().find("approvals=1/2") != std::string::npos,
        "a scripted session creates a request and lists it");
}

std::int64_t addDispute(StaffRig& r, std::int64_t seq, std::int64_t ageSeconds)
{
    if (!r.accounts.find("ACC-1")) r.accounts.insert(AccountRecord{ "ACC-1", "Owner", 1000000 });
    const std::int64_t id = r.txs.insertHeld(kAtmA, "S-" + std::to_string(seq), "ACC-1", 50000, static_cast<std::uint64_t>(seq), r.clock.nowUnix() - ageSeconds);
    if (!r.txs.setStatus(id, TxStatus::Uncertain, r.clock.nowUnix(), "reconciliation", "no_report_in_time")) throw std::runtime_error("test: cannot make a dispute");
    return id;
}

void disputeTests()
{
    section("Disputed transactions");

    StaffRig r;
    const std::int64_t day = r.config.manualResolutionAfterSeconds;
    const std::int64_t old = addDispute(r, 1, day + 60);
    const std::int64_t fresh = addDispute(r, 2, 60);
    const std::string a1 = r.consoleToken("A-01");
    const std::string a2 = r.consoleToken("A-02");

    const auto list = r.console.disputes(a1);
    check(list.size() == 1 && list.front().id == old, "only transactions uncertain for more than 24 hours are listed");
    check(r.console.disputes("").empty(), "nobody else sees them");
    check(r.console.proposeResolution(a1, fresh, false, "too_early").verdict == Verdict::Denied, "a younger one cannot be resolved by hand yet");
    check(r.console.proposeResolution(a1, old, false, "has spaces").verdict == Verdict::Denied, "the reason is a single word");

    const Decision d = r.console.proposeResolution(a1, old, false, "cassette_jam_confirmed_on_site");
    check(d.verdict == Verdict::PendingApproval, "an admin proposes a reversal with a reason");
    check(r.txs.findById(old)->status == TxStatus::Uncertain, "nothing changes on one admin's word");
    check(r.console.approve(a1, d.requestId).result == ApprovalResult::AlreadyApproved, "the same admin cannot approve it");

    const ConsoleApproval second = r.console.approve(a2, d.requestId);
    check(second.result == ApprovalResult::Approved && second.resolved == ResolveResult::Resolved && !second.queued, "a second admin's approval resolves it on the server");
    const auto tx = r.txs.findById(old);
    check(tx && tx->status == TxStatus::Reversed && tx->resolvedBy == DisputeService::resolvedBy(d.requestId) && tx->reason == "cassette_jam_confirmed_on_site",
        "it is reversed, with who decided and why");
    check(r.accounts.balance("ACC-1") == 1000000, "a reversal takes no money");
    check(r.dual.get(d.requestId)->status == RequestStatus::Executed, "the request is executed");
    check(r.disputes.executeApproved(d.requestId) == ResolveResult::AlreadyResolved, "and cannot run twice");
    check(r.console.disputes(a1).empty(), "the dispute leaves the list");

    StaffRig c;
    const std::int64_t paid = addDispute(c, 1, day + 60);
    const Decision commit = c.console.proposeResolution(c.consoleToken("A-01"), paid, true, "counted_at_collection");
    check(c.console.approve(c.consoleToken("A-02"), commit.requestId).resolved == ResolveResult::Resolved, "a commit is resolved the same way");
    check(c.txs.findById(paid)->status == TxStatus::Committed && c.accounts.balance("ACC-1") == 1000000 - 50000, "and the money is debited once");

    StaffRig crash;
    const std::int64_t lost = addDispute(crash, 1, day + 60);
    const Decision open = crash.console.proposeResolution(crash.consoleToken("A-01"), lost, false, "jam");
    check(crash.approvals.approve(open.requestId, crash.consoleToken("A-02")) == ApprovalResult::Approved, "an approval lands but the server stops before acting on it");
    check(crash.txs.findById(lost)->status == TxStatus::Uncertain, "the transaction is still open");
    check(crash.disputes.tick() == 1 && crash.txs.findById(lost)->status == TxStatus::Reversed, "the next tick finishes it");
}

void argon2Tests()
{
    section("Argon2id verifier");
    const auto hash = hashPasswordArgon2id(kPassword);
    check(hash && hash->rfind("$argon2id$", 0) == 0, "the hash is an argon2id string the staff table accepts");
    const PasswordCheckFn verify = makeArgon2idVerifier();
    check(hash && verify(*hash, kPassword), "the right password verifies");
    check(hash && !verify(*hash, "wrong"), "a wrong password does not");
    check(!verify("not a hash", kPassword), "a malformed hash does not verify");
    const std::string dummy = makeDummyArgon2idHash();
    check(dummy.rfind("$argon2id$", 0) == 0 && !verify(dummy, kPassword), "the dummy hash looks real and matches nothing");
}

}

int main()
{
    staffRepositoryTests();
    loginTests();
    lockoutTests();
    logoutAndTokenTests();
    accessDeciderTests();
    dualControlRepositoryTests();
    commandTests();
    consoleTests();
    disputeTests();
    argon2Tests();
    return gabella_test::summary();
}

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "Check.h"

#include "access/AccessClient.h"
#include "access/AccessControl.h"
#include "access/ApprovalPolicy.h"
#include "access/DualControlManager.h"
#include "access/IStaffAuthenticator.h"
#include "access/InMemoryDualControlRepository.h"
#include "access/PermissionTable.h"
#include "access/SessionRegistry.h"
#include "access/StaffTokenStore.h"
#include "audit/DataPolicy.h"
#include "audit/FakeAuditSink.h"
#include "common/Clock.h"

using gabella_test::check;
using gabella_test::section;

namespace
{

    const std::string kPassword = "S3cretPass";
    const std::int64_t kStart = 1792000000;

    RandomBytesFn makeRng()
    {
        auto counter = std::make_shared<std::uint64_t>(0);
        return [counter](std::size_t n) -> std::optional<std::string>
            {
                std::string out(n, 'x');
                std::uint64_t v = (*counter)++;
                for (std::size_t i = 0; i < n && i < 8; ++i)
                {
                    out[n - 1 - i] = static_cast<char>(v & 0xFF);
                    v >>= 8;
                }
                return out;
            };
    }

    std::size_t count(const FakeAuditSink& sink, EventType t)
    {
        std::size_t n = 0;
        for (const LogEvent& e : sink.events())
        {
            if (e.type == t) ++n;
        }
        return n;
    }

    struct Rig
    {
        FakeClock clock{ kStart };
        FakeAuditSink sink;
        PermissionTable permissions = PermissionTable::makeDefault();
        ApprovalPolicy policy = ApprovalPolicy::makeDefault();
        InMemoryDualControlRepository repo;
        std::uint32_t admins = 3;
        DualControlManager dual{ repo, policy, clock, sink, makeRng(), [this] { return admins; } };
        SessionRegistry sessions{ clock };
        StaffTokenStore tokens{ clock, makeRng() };
        InMemoryStaffAuthenticator auth;
        AccessControl access{ permissions, dual, sessions, tokens, auth, sink };

        Rig()
        {
            auth.addUser("A-01", kPassword, Role::Admin);
            auth.addUser("A-02", kPassword, Role::Admin);
            auth.addUser("A-03", kPassword, Role::Admin);
            auth.addUser("E-01", kPassword, Role::ServiceEngineer);
            auth.addUser("C-01", kPassword, Role::CashCollector);
            auth.addUser("AU-01", kPassword, Role::Auditor);
        }

        std::string login(const std::string& staffId, const std::string& atmId = kAdminConsoleAtmId)
        {
            auto r = access.staffLogin(staffId, kPassword, atmId);
            return r ? r->token : std::string();
        }

        static AccessRequest staffReq(const std::string& token, Action a,
            const std::string& params = "", const std::string& atmId = kAdminConsoleAtmId)
        {
            AccessRequest q;
            q.atmId = atmId;
            q.staffToken = token;
            q.action = a;
            q.params = params;
            return q;
        }

        static AccessRequest sessionReq(const std::string& sessionId, Action a,
            const std::string& atmId = "ATM-001")
        {
            AccessRequest q;
            q.atmId = atmId;
            q.sessionId = sessionId;
            q.action = a;
            return q;
        }
    };

    void permissionTableTests()
    {
        section("PermissionTable (U29)");
        using R = Role;
        using A = Action;

        struct Pair { Role r; Action a; };
        const Pair granted[] = {
            { R::Client, A::CheckBalance }, { R::Client, A::Withdraw },
            { R::ServiceEngineer, A::LoadCash }, { R::ServiceEngineer, A::RunDiagnostics },
            { R::CashCollector, A::CollectCash },
            { R::Auditor, A::ReadLog }, { R::Auditor, A::VerifyLog },
            { R::Admin, A::UpdateWorkingKey }, { R::Admin, A::InstallMasterKey },
            { R::Admin, A::RestoreFromOutOfService }, { R::Admin, A::ResolveTransaction }
        };
        const Role roles[] = { R::Client, R::ServiceEngineer, R::CashCollector, R::Auditor, R::Admin, R::System };
        const Action actions[] = { A::CheckBalance, A::Withdraw, A::LoadCash, A::RunDiagnostics, A::CollectCash,
            A::ReadLog, A::VerifyLog, A::UpdateWorkingKey, A::InstallMasterKey,
            A::RestoreFromOutOfService, A::ResolveTransaction };

        const PermissionTable table = PermissionTable::makeDefault();
        bool all = true;
        int allowedCount = 0;
        for (Role r : roles)
        {
            for (Action a : actions)
            {
                bool expected = false;
                for (const Pair& p : granted)
                {
                    if (p.r == r && p.a == a) expected = true;
                }
                const bool got = table.isAllowed(r, a);
                if (got != expected) all = false;
                if (got) ++allowedCount;
            }
        }
        check(all, "every role/action pair matches table 7.4");
        check(allowedCount == 11, "exactly 11 permissions are granted, everything else is denied");
        check(!table.isAllowed(Role::System, Action::Withdraw), "System role has no rights");
    }

    void approvalPolicyTests()
    {
        section("ApprovalPolicy (U30)");

        const ApprovalPolicy p = ApprovalPolicy::makeDefault();
        check(p.requiredApprovals(2) == 2, "2 admins -> 2");
        check(p.requiredApprovals(3) == 2, "3 admins -> 2");
        check(p.requiredApprovals(4) == 3, "4 admins -> 3");
        check(p.requiredApprovals(6) == 4, "6 admins -> 4");
        check(p.requiredApprovals(0) == 2 && p.requiredApprovals(1) == 2, "minimum is always 2");
        check(p.ttlSeconds == 1800, "request lives 30 minutes");
        check(p.isCritical(Action::UpdateWorkingKey) && p.isCritical(Action::InstallMasterKey)
            && p.isCritical(Action::RestoreFromOutOfService) && p.isCritical(Action::ResolveTransaction),
            "the four critical actions are critical");
        check(!p.isCritical(Action::Withdraw) && !p.isCritical(Action::LoadCash),
            "ordinary actions are not critical");
    }

    void tokenTests()
    {
        section("StaffTokenStore (U33)");

        FakeClock clock{ kStart };
        StaffTokenStore tokens(clock, makeRng());

        const std::string t = tokens.issue("E-01", Role::ServiceEngineer, "ATM-001");
        check(t.size() == 32, "token is 128 bits in hex");
        check(tokens.issue("E-01", Role::ServiceEngineer, "ATM-001") != t, "tokens are unique");

        auto who = tokens.resolve(t);
        check(who && who->staffId == "E-01" && who->role == Role::ServiceEngineer && who->atmId == "ATM-001",
            "resolve returns staff, role and ATM");
        check(!tokens.resolve("unknown").has_value(), "unknown token is rejected");

        clock.advance(14 * 60);
        check(tokens.resolve(t).has_value(), "14 minutes of idleness is still valid");
        clock.advance(16 * 60);
        check(!tokens.resolve(t).has_value(), "16 minutes of idleness expires the token");

        const std::string active = tokens.issue("A-01", Role::Admin, kAdminConsoleAtmId);
        bool alwaysValid = true;
        for (int i = 0; i < 40; ++i)
        {
            clock.advance(12 * 60);
            alwaysValid = alwaysValid && tokens.resolve(active).has_value();
        }
        check(alwaysValid, "an active token stays valid for the whole 8 hours");
        clock.advance(60);
        check(!tokens.resolve(active).has_value(), "an active token dies after 8 h 1 min");

        const std::string r = tokens.issue("C-01", Role::CashCollector, "ATM-001");
        tokens.revoke(r);
        check(!tokens.resolve(r).has_value(), "revoked token is rejected");

        (void)tokens.issue("AU-01", Role::Auditor, "ATM-001");
        (void)tokens.issue("AU-01", Role::Auditor, "ATM-001");
        clock.advance(16 * 60);
        tokens.purgeExpired();
        check(tokens.activeCount() == 0, "purgeExpired removes expired tokens");

        StaffTokenStore broken(clock, [](std::size_t) { return std::optional<std::string>(); });
        bool threw = false;
        try { (void)broken.issue("E-01", Role::ServiceEngineer, "ATM-001"); }
        catch (const std::runtime_error&) { threw = true; }
        check(threw, "no token is issued when the random source fails");
    }

    void sessionTests()
    {
        section("SessionRegistry");

        FakeClock clock{ kStart };
        SessionRegistry sessions(clock);
        check(!sessions.isOpen("S1"), "unknown session is closed");
        sessions.open("S1");
        check(sessions.isOpen("S1"), "opened session is open");
        clock.advance(179);
        check(sessions.isOpen("S1"), "still open after 179 s");
        clock.advance(2);
        check(!sessions.isOpen("S1"), "closed after 3 minutes");

        sessions.open("S2");
        sessions.close("S2");
        check(!sessions.isOpen("S2"), "close ends the session");
        sessions.open("");
        check(!sessions.isOpen(""), "empty session id is never open");

        sessions.open("S3");
        clock.advance(200);
        sessions.purgeExpired();
        check(!sessions.isOpen("S3"), "purgeExpired removes expired sessions");
    }

    void dualControlTests()
    {
        section("DualControlManager (U31, U32, A10, A11)");

        Rig r;
        const auto id = r.dual.open("A-01", Action::RestoreFromOutOfService, "ATM-01");
        check(id.has_value() && id->rfind("DC-", 0) == 0, "open creates a request");
        if (!id) return;

        auto req = r.dual.get(*id);
        check(req && req->status == RequestStatus::Pending && req->requiredApprovals == 2
            && req->approvers.size() == 1 && req->initiatorId == "A-01"
            && req->params == "ATM-01" && req->expiresAt == req->createdAt + 1800,
            "request is Pending, threshold 2 of 3 stored, initiator counted");

        check(r.dual.approve(*id, "A-01") == ApprovalResult::AlreadyApproved,
            "U31/A10: initiator cannot approve twice");
        check(r.dual.get(*id)->approvers.size() == 1, "U31: approvals did not grow");

        check(r.dual.approve(*id, "A-02") == ApprovalResult::Approved, "second admin reaches the threshold");
        check(r.dual.get(*id)->status == RequestStatus::Approved, "status is Approved");
        check(r.dual.approve(*id, "A-02") == ApprovalResult::AlreadyApproved, "repeat approval is refused");
        check(r.dual.approve(*id, "A-03") == ApprovalResult::NotEligible,
            "an approved request takes no more approvals");

        check(r.dual.markExecuted(*id), "markExecuted works once");
        check(!r.dual.markExecuted(*id), "U32: second markExecuted is false");
        check(r.dual.get(*id)->status == RequestStatus::Executed, "status is Executed");
        check(count(r.sink, EventType::DUAL_CONTROL_REQUESTED) == 1
            && count(r.sink, EventType::DUAL_CONTROL_APPROVED) == 1
            && count(r.sink, EventType::DUAL_CONTROL_EXECUTED) == 1,
            "every state change is logged exactly once");

        const auto late = r.dual.open("A-01", Action::UpdateWorkingKey, "Mac");
        r.clock.advance(31 * 60);
        check(r.dual.get(*late)->status == RequestStatus::Expired, "get reports a stale request as Expired");
        check(r.dual.approve(*late, "A-02") == ApprovalResult::Expired, "U32: approval after 31 min -> Expired");
        check(r.dual.approve(*late, "A-03") == ApprovalResult::Expired, "expired stays expired");
        check(r.dual.listPending().empty(), "expired requests are not listed as pending");

        check(r.dual.approve("DC-ffff-ffff-ffff-ffff", "A-02") == ApprovalResult::UnknownRequest,
            "unknown request id");
        check(r.dual.approve(*late, "") == ApprovalResult::NotEligible, "empty approver id is refused");
        check(!r.dual.open("A-01", Action::Withdraw, "").has_value(), "ordinary action cannot be opened");
        check(!r.dual.open("", Action::UpdateWorkingKey, "Mac").has_value(), "empty initiator is refused");

        Rig p;
        const auto bound = p.dual.open("A-01", Action::RestoreFromOutOfService, "ATM-01");
        check(!p.dual.getApproved(*bound, Action::RestoreFromOutOfService, "ATM-01").has_value(),
            "A11: a pending request is not executable");
        (void)p.dual.approve(*bound, "A-02");
        check(p.dual.getApproved(*bound, Action::RestoreFromOutOfService, "ATM-01").has_value(),
            "A11: the approved request is executable with its own parameters");
        check(!p.dual.getApproved(*bound, Action::RestoreFromOutOfService, "ATM-99").has_value(),
            "A11: other parameters are refused");
        check(!p.dual.getApproved(*bound, Action::UpdateWorkingKey, "ATM-01").has_value(),
            "A11: other action is refused");

        Rig few;
        few.admins = 1;
        check(!few.dual.open("A-01", Action::UpdateWorkingKey, "Mac").has_value(),
            "a single admin cannot open a critical request");
        few.admins = 4;
        const auto four = few.dual.open("A-01", Action::UpdateWorkingKey, "Mac");
        check(four && few.dual.get(*four)->requiredApprovals == 3, "threshold is computed at creation: 3 of 4");
        check(few.dual.approve(*four, "A-02") == ApprovalResult::StillPending, "2 of 3: still pending");
        few.admins = 10;
        check(few.dual.get(*four)->requiredApprovals == 3, "adding admins later does not change the threshold");
        check(few.dual.approve(*four, "A-03") == ApprovalResult::Approved, "3 of 3: approved");

        Rig a;
        a.sink.setFail(true);
        check(!a.dual.open("A-01", Action::UpdateWorkingKey, "Mac").has_value()
            && a.repo.listPending().empty(), "audit down: no request is created");
        a.sink.setFail(false);
        const auto ok = a.dual.open("A-01", Action::UpdateWorkingKey, "Mac");
        a.sink.setFail(true);
        check(a.dual.approve(*ok, "A-02") == ApprovalResult::AuditUnavailable, "audit down: approval refused");
        check(a.dual.get(*ok)->approvers.size() == 1 && a.dual.get(*ok)->status == RequestStatus::Pending,
            "audit down: state unchanged");
        a.sink.setFail(false);
        (void)a.dual.approve(*ok, "A-02");
        a.sink.setFail(true);
        check(!a.dual.markExecuted(*ok) && a.dual.get(*ok)->status == RequestStatus::Approved,
            "audit down: markExecuted refused, status unchanged");

        InMemoryDualControlRepository repo;
        CriticalRequest x;
        x.requestId = "X";
        (void)repo.inTransaction([&] { (void)repo.insertRequest(x); return false; });
        check(!repo.find("X").has_value(), "transaction rolls back when the callback returns false");
    }

    void decideTests()
    {
        section("AccessControl::decide (U34, A09)");

        Rig r;
        const std::string eng = r.login("E-01", "ATM-001");
        const std::string col = r.login("C-01", "ATM-001");
        check(!eng.empty() && !col.empty(), "setup: staff logged in");

        check(r.access.decide(Rig::staffReq(eng, Action::LoadCash, "", "ATM-001")).verdict == Verdict::Allowed,
            "engineer may load cash");
        check(r.access.decide(Rig::staffReq(eng, Action::RunDiagnostics, "", "ATM-001")).verdict == Verdict::Allowed,
            "engineer may run diagnostics");

        Decision d = r.access.decide(Rig::staffReq(col, Action::Withdraw, "", "ATM-001"));
        check(d.verdict == Verdict::Denied && d.reason == DenyReason::NotPermitted,
            "U34: collector token cannot withdraw");
        check(count(r.sink, EventType::ACCESS_DENIED) == 1, "denial is logged as ACCESS_DENIED");

        AccessRequest anon;
        anon.atmId = "ATM-001";
        anon.action = Action::RestoreFromOutOfService;
        d = r.access.decide(anon);
        check(d.verdict == Verdict::Denied && d.reason == DenyReason::NotLoggedIn,
            "A09: admin action without a token is NotLoggedIn");
        d = r.access.decide(Rig::staffReq("forged-token", Action::RestoreFromOutOfService, "", "ATM-001"));
        check(d.verdict == Verdict::Denied && d.reason == DenyReason::NotLoggedIn, "A09: forged token is NotLoggedIn");

        d = r.access.decide(Rig::staffReq(eng, Action::LoadCash, "", "ATM-002"));
        check(d.verdict == Verdict::Denied && d.reason == DenyReason::NotLoggedIn,
            "a token does not work from another ATM");

        r.sessions.open("S1");
        check(r.access.decide(Rig::sessionReq("S1", Action::Withdraw)).verdict == Verdict::Allowed,
            "client session may withdraw");
        check(r.access.decide(Rig::sessionReq("S1", Action::CheckBalance)).verdict == Verdict::Allowed,
            "client session may check balance");
        d = r.access.decide(Rig::sessionReq("S1", Action::LoadCash));
        check(d.verdict == Verdict::Denied && d.reason == DenyReason::NotPermitted, "client cannot load cash");
        d = r.access.decide(Rig::sessionReq("S9", Action::Withdraw));
        check(d.verdict == Verdict::Denied && d.reason == DenyReason::NoSession, "unknown session is refused");
        r.sessions.close("S1");
        check(r.access.decide(Rig::sessionReq("S1", Action::Withdraw)).reason == DenyReason::NoSession,
            "closed session is refused");

        r.clock.advance(16 * 60);
        check(r.access.decide(Rig::staffReq(eng, Action::LoadCash, "", "ATM-001")).reason == DenyReason::NotLoggedIn,
            "expired token is refused");

        const std::string adm = r.login("A-01");
        const std::string eng2 = r.login("E-01", "ATM-001");
        d = r.access.decide(Rig::staffReq(eng2, Action::RestoreFromOutOfService, "ATM-01"));
        check(d.verdict == Verdict::Denied && d.reason == DenyReason::NotLoggedIn,
            "engineer token issued for ATM-001 is useless against the console");
        const std::string eng3 = r.login("E-01", kAdminConsoleAtmId);
        d = r.access.decide(Rig::staffReq(eng3, Action::RestoreFromOutOfService, "ATM-01"));
        check(d.verdict == Verdict::Denied && d.reason == DenyReason::NotPermitted
            && r.repo.listPending().empty(), "engineer cannot open a critical request");

        d = r.access.decide(Rig::staffReq(adm, Action::RestoreFromOutOfService, "ATM-01"));
        check(d.verdict == Verdict::PendingApproval && !d.requestId.empty(),
            "admin: critical action returns PendingApproval with a request id");
        check(r.dual.get(d.requestId).has_value(), "the request exists in dual control");

        r.admins = 1;
        d = r.access.decide(Rig::staffReq(adm, Action::UpdateWorkingKey, "Mac"));
        check(d.verdict == Verdict::Denied, "a lone admin cannot start a critical action");

        check(r.access.isPermitted(Role::Client, Action::Withdraw), "isPermitted: Client may withdraw");
        check(!r.access.isPermitted(Role::Client, Action::LoadCash), "isPermitted: Client may not load cash");
    }

    void loginTests()
    {
        section("AccessControl::staffLogin / approve");

        Rig r;
        auto ok = r.access.staffLogin("E-01", kPassword, "ATM-001");
        check(ok && ok->role == Role::ServiceEngineer && ok->token.size() == 32, "login returns token and role");
        check(count(r.sink, EventType::STAFF_LOGIN) == 1, "successful login is logged");

        check(!r.access.staffLogin("E-01", "wrong", "ATM-001").has_value(), "wrong password is refused");
        check(!r.access.staffLogin("NOBODY", kPassword, "ATM-001").has_value(), "unknown staff is refused");
        check(!r.access.staffLogin("E-01", kPassword, "").has_value(), "login without an ATM id is refused");
        check(!r.access.staffLogin("E-01", "", "ATM-001").has_value(), "empty password is refused");
        check(count(r.sink, EventType::STAFF_LOGIN) == 3, "failed logins are logged too");

        bool leak = false;
        for (const LogEvent& e : r.sink.events())
        {
            if (e.details.find(kPassword) != std::string::npos
                || e.actorId.find(kPassword) != std::string::npos
                || (ok && e.details.find(ok->token) != std::string::npos))
                leak = true;
        }
        check(!leak, "neither password nor token reaches the log");

        r.access.staffLogout(ok->token);
        check(!r.tokens.resolve(ok->token).has_value(), "logout revokes the token");

        r.sink.setFail(true);
        const std::size_t before = r.tokens.activeCount();
        check(!r.access.staffLogin("E-01", kPassword, "ATM-001").has_value(), "audit down: login refused");
        check(r.tokens.activeCount() == before, "audit down: no token is left behind");
        r.sink.setFail(false);

        const std::string a1 = r.login("A-01");
        const std::string a2 = r.login("A-02");
        const std::string eng = r.login("E-01");
        const auto d = r.access.decide(Rig::staffReq(a1, Action::UpdateWorkingKey, "Mac"));
        check(r.access.approve(d.requestId, eng) == ApprovalResult::NotEligible, "non-admin cannot approve");
        check(r.access.approve(d.requestId, "forged") == ApprovalResult::NotEligible, "forged token cannot approve");
        check(r.access.approve(d.requestId, a1) == ApprovalResult::AlreadyApproved, "A10: initiator cannot self-approve");
        check(r.access.approve("DC-ffff-ffff-ffff-ffff", a2) == ApprovalResult::UnknownRequest, "unknown request");
        check(r.access.approve(d.requestId, a2) == ApprovalResult::Approved, "second admin approves");
    }

    void endToEndTests()
    {
        section("Dual control end to end (I14, I15: access part)");

        Rig r;
        const std::string a = r.login("A-01");
        const std::string b = r.login("A-02");

        const Decision created = r.access.decide(Rig::staffReq(a, Action::RestoreFromOutOfService, "ATM-01"));
        check(created.verdict == Verdict::PendingApproval, "I14: admin A creates RestoreFromOutOfService");
        check(r.access.approve(created.requestId, b) == ApprovalResult::Approved, "I14: admin B approves");
        check(r.dual.getApproved(created.requestId, Action::RestoreFromOutOfService, "ATM-01").has_value(),
            "I14: BankServer may now sign the command");
        check(r.dual.markExecuted(created.requestId), "I14: request is marked EXECUTED");
        check(!r.dual.markExecuted(created.requestId), "I14: it cannot be executed twice");

        const Decision key = r.access.decide(Rig::staffReq(b, Action::UpdateWorkingKey, "Mac"));
        check(key.verdict == Verdict::PendingApproval, "I15: UpdateWorkingKey goes through dual control");
        check(r.access.approve(key.requestId, a) == ApprovalResult::Approved, "I15: second admin approves");

        bool allLoggable = true;
        for (const LogEvent& e : r.sink.events())
        {
            if (!isLoggable(e)) allLoggable = false;
        }
        check(allLoggable, "every event written by module 4 passes the audit data policy");
    }

    struct FakeDecider final : IAccessDecider
    {
        Decision next;
        bool throws = false;
        int calls = 0;
        AccessRequest last;

        Decision decide(const AccessRequest& request) override
        {
            ++calls;
            last = request;
            if (throws) throw std::runtime_error("link down");
            return next;
        }
    };

    void accessClientTests()
    {
        section("AccessClient (ATM side)");

        FakeDecider server;
        AccessClient client(server, "ATM-001");
        IAccessClient& iface = client;

        server.next.verdict = Verdict::Allowed;
        check(iface.isAllowed("tok", Action::LoadCash), "Allowed from the server -> true");
        check(server.last.atmId == "ATM-001" && server.last.staffToken == "tok"
            && server.last.action == Action::LoadCash && server.last.sessionId.empty(),
            "request carries atmId, token and action, but no role");

        server.next.verdict = Verdict::Denied;
        check(!iface.isAllowed("tok", Action::LoadCash), "Denied -> false");
        server.next.verdict = Verdict::PendingApproval;
        check(!iface.isAllowed("tok", Action::RestoreFromOutOfService), "PendingApproval -> false on the ATM");

        server.next.verdict = Verdict::Allowed;
        server.throws = true;
        check(!iface.isAllowed("tok", Action::LoadCash), "link error means no (fail-closed)");
        server.throws = false;

        const int before = server.calls;
        check(!iface.isAllowed("", Action::LoadCash) && server.calls == before,
            "empty token is refused without asking the server");

        check(iface.isVisible(Role::Client, Action::Withdraw), "UI: client sees Withdraw");
        check(!iface.isVisible(Role::Client, Action::LoadCash), "UI: client does not see LoadCash");
        check(iface.isVisible(Role::ServiceEngineer, Action::LoadCash), "UI: engineer sees LoadCash");
    }

}

int main()
{
    permissionTableTests();
    approvalPolicyTests();
    tokenTests();
    sessionTests();
    dualControlTests();
    decideTests();
    loginTests();
    endToEndTests();
    accessClientTests();

    return gabella_test::summary();
}
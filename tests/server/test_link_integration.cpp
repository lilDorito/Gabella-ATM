#include <iostream>
#include <string>

#include "Check.h"
#include "ReconRig.h"
#include "ServerRig.h"
#include "access/AccessClient.h"
#include "atm/PendingReportQueue.h"
#include "atm/ServerLink.h"
#include "audit/CheckpointPayload.h"
#include "crypto/PinModule.h"

using gabella_test::check;
using gabella_test::section;

namespace
{
class ToggleApi final : public IServerApi
{
private:
    IServerApi& _real;

public:
    bool down = false;

    explicit ToggleApi(IServerApi& real) : _real(real) {}

    AuthResponse authorize(const AuthRequest& request) override
    {
        if (down)
        {
            AuthResponse refused;
            refused.sessionId = request.getSessionId();
            return refused;
        }
        return _real.authorize(request);
    }
    bool reportDispense(const RequestHeader& h, const DispenseReport& r) override { return !down && _real.reportDispense(h, r); }
    bool syncStatus(const RequestHeader& h, const StatusReport& r) override { return !down && _real.syncStatus(h, r); }
    bool endSession(const RequestHeader& h, const std::string& s) override { return !down && _real.endSession(h, s); }
    std::optional<StaffLoginResult> staffLogin(const RequestHeader& h, const StaffLoginRequest& r) override { return down ? std::nullopt : _real.staffLogin(h, r); }
    bool staffLogout(const RequestHeader& h, const std::string& t) override { return !down && _real.staffLogout(h, t); }
    Decision decide(const RequestHeader& h, const AccessRequest& r) override { return down ? Decision{} : _real.decide(h, r); }
    bool submitCheckpoint(const RequestHeader& h, const Checkpoint& c) override { return !down && _real.submitCheckpoint(h, c); }
    std::optional<SignedCheckpoint> latestCheckpoint(const RequestHeader& h, const std::string& t) override { return down ? std::nullopt : _real.latestCheckpoint(h, t); }
    bool reportTamper(const RequestHeader& h) override { return !down && _real.reportTamper(h); }
    std::vector<SignedCommand> pollCommands(const RequestHeader& h) override { return down ? std::vector<SignedCommand>{} : _real.pollCommands(h); }
    bool reportCommandResult(const RequestHeader& h, std::uint64_t seq, bool ok) override { return !down && _real.reportCommandResult(h, seq, ok); }
};

struct Stack : ReconRig
{
    ToggleApi api{ reconServer };
    PendingReportQueue queue;
    ServerLink link{ api, *fx.atm, queue, clock, kRigAtm };
};

void reportTests()
{
    section("Dispense reports through the link");

    Stack s;
    s.hold(1);
    s.link.reportDispense(s.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50)));
    check(s.status(1) == TxStatus::Committed && s.queue.empty(), "a report sent through the link settles the transaction");
    check(s.balance() == 950000 && s.expected() == counts(50, 50, 49, 50), "the account is debited and the expected counters follow");

    s.hold(2);
    s.link.reportDispense(s.dispenseReport(2, DispenseResult::HardwareFault, counts(50, 50, 49, 50)));
    check(s.status(2) == TxStatus::Reversed && s.balance() == 950000, "a failure report reverses the transaction");

    Stack outage;
    outage.hold(1);
    outage.api.down = true;
    outage.link.reportDispense(outage.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50)));
    check(outage.queue.size() == 1 && outage.status(1) == TxStatus::Held, "a report sent during an outage is queued");
    outage.clock.advance(300);
    check(outage.recon.tick() == 1 && outage.status(1) == TxStatus::Uncertain, "meanwhile the server marks the transaction uncertain");
    outage.api.down = false;
    check(outage.link.flushPending() && outage.queue.empty(), "after the outage the queue is delivered");
    check(outage.status(1) == TxStatus::Committed && outage.balance() == 950000, "the late report, sent with a fresh header, settles the uncertain transaction");

    Stack twice;
    twice.hold(1);
    const DispenseReport once = twice.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50));
    twice.link.reportDispense(once);
    twice.link.reportDispense(once);
    check(twice.status(1) == TxStatus::Committed && twice.balance() == 950000, "sending the same report twice debits only once");
}

void statusTests()
{
    section("Status reports through the link");

    Stack s;
    s.hold(1);
    s.hold(2, 20000);
    check(s.link.syncStatus(s.statusReport(StatusReason::Reconnect, 2, counts(50, 49, 49, 50))), "a reconnect report is accepted");
    check(s.status(1) == TxStatus::Committed && s.status(2) == TxStatus::Committed && s.balance() == 930000, "it settles the transactions the ATM never reported");

    Stack lost;
    lost.hold(1);
    lost.api.down = true;
    lost.link.reportDispense(lost.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50)));
    check(!lost.link.syncStatus(lost.statusReport(StatusReason::Reconnect, 1, counts(50, 50, 49, 50))), "a status report is not accepted while the server is away");
    lost.api.down = false;
    check(lost.link.syncStatus(lost.statusReport(StatusReason::Reconnect, 1, counts(50, 50, 49, 50))) && lost.queue.empty(),
        "afterwards the waiting report goes out first and the status report is accepted");
    check(lost.status(1) == TxStatus::Committed && lost.balance() == 950000, "and the transaction is settled exactly once");

    Stack staff;
    check(staff.link.syncStatus(staff.statusReport(StatusReason::CashLoaded, 0, counts(60, 60, 60, 60), "tok-eng")), "an engineer's load report is accepted");
    check(staff.expected() == counts(60, 60, 60, 60), "the server's expectation follows the load");
    check(!staff.link.syncStatus(staff.statusReport(StatusReason::CashLoaded, 0, counts(1, 1, 1, 1), "tok-col")), "a collector's token cannot change the expectation");
    check(staff.expected() == counts(60, 60, 60, 60), "the expectation is unchanged");
}

void accessTests()
{
    section("Access decisions through the link");

    Stack s;
    AccessRequest ask;
    ask.staffToken = "tok-eng";
    ask.action = Action::LoadCash;
    check(s.link.decide(ask).verdict == Verdict::Allowed, "the server allows an engineer to load cash");
    ask.staffToken = "tok-col";
    check(s.link.decide(ask).verdict == Verdict::Denied, "and denies a collector");

    AccessClient client(s.link, kRigAtm);
    check(client.isAllowed("tok-eng", Action::LoadCash) && !client.isAllowed("tok-col", Action::LoadCash), "the ATM's AccessClient works on top of the link");
    s.api.down = true;
    check(!client.isAllowed("tok-eng", Action::LoadCash), "and refuses when the server is away");
}

void authorizeTests()
{
    section("Authorization through the link");

    Stack s;
    PinModule pin(*s.fx.atm);
    const auto request = pin.processPin(Card("4111111111111111", 12, 2030), "4821", Action::CheckBalance, 0, "session-1", kRigAtm, s.clock.nowUnix());
    check(request.has_value(), "the ATM builds a MACed request");

    const auto answer = s.link.authorize(*request);
    check(answer && answer->status == AuthStatus::Error, "a validly signed answer, even a refusal, reaches the ATM");

    const AuthRequest altered(
        request->getAtmId(), request->getSessionId(), request->getAction(), request->getCiphertext(), request->getNonce(), request->getTimestamp(), request->getPan(), 999900, request->getMac());
    check(!s.link.authorize(altered), "a request altered after it was MACed gets an unsigned refusal, which the link drops");
    check(s.count(EventType::ACCESS_DENIED) >= 1, "the server logged the refusal");

    s.api.down = true;
    check(!s.link.authorize(*request), "an unreachable server gives no answer");
}

void checkpointTests()
{
    section("Checkpoints through the link");

    Stack s;
    Checkpoint cp;
    cp.logId = kRigAtm;
    cp.seqNo = 5;
    cp.hash = std::string(64, 'c');
    cp.timestamp = s.clock.nowUnix();
    cp.mac = *s.fx.atm->macAudit(checkpointPayload(cp));

    check(s.link.submit(cp), "a checkpoint is submitted");
    check(s.checkpoints.latest(kRigAtm) && s.checkpoints.latest(kRigAtm)->seqNo == 5, "the server stored it");

    const std::string auditor = s.tokens.issue("AU-01", Role::Auditor, kRigAtm);
    const std::string nonce = *s.fx.atm->generateNonce();
    const auto reply = s.link.latestCheckpoint(auditor, nonce);
    check(reply && reply->checkpoint.seqNo == 5 && reply->requestNonce == nonce, "an auditor gets the stored checkpoint back with the request's nonce");
    check(reply && s.fx.atm->verifyServer(SignDomain::Checkpoint, reply->signedPayload(), reply->signature), "the answer carries the server's signature");
    check(!s.link.latestCheckpoint("tok-nobody", *s.fx.atm->generateNonce()), "a token that is not an auditor's gets nothing");

    Stack outage;
    Checkpoint cp2 = cp;
    cp2.timestamp = outage.clock.nowUnix();
    cp2.mac = *outage.fx.atm->macAudit(checkpointPayload(cp2));
    outage.api.down = true;
    check(outage.link.submit(cp2) && outage.queue.size() == 1, "a checkpoint is queued during an outage");
    outage.api.down = false;
    check(outage.link.flushPending() && outage.checkpoints.latest(kRigAtm).has_value(), "and reaches the server afterwards");
}

void tamperTests()
{
    section("Tamper through the link");

    Stack s;
    s.link.reportTamper();
    check(s.atms.find(kRigAtm)->status == AtmStatus::OutOfService, "the server takes the ATM out of service");

    AccessRequest ask;
    ask.staffToken = "tok-eng";
    ask.action = Action::LoadCash;
    check(s.link.decide(ask).verdict == Verdict::Denied, "an out-of-service ATM is refused access decisions");

    s.hold(1);
    s.link.reportDispense(s.dispenseReport(1, DispenseResult::HardwareFault, kFull));
    check(s.status(1) == TxStatus::Reversed, "but its reports are still taken, so held money can be released");
}
}

int main()
{
    gabella_test::banner("ATM link and server integration test suite");
    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return 1;
    }

    reportTests();
    statusTests();
    accessTests();
    authorizeTests();
    checkpointTests();
    tamperTests();

    return gabella_test::summary();
}

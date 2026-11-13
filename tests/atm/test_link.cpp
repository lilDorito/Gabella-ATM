#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "Check.h"
#include "FakeServerApi.h"
#include "HsmFixture.h"

#include "atm/PendingReportQueue.h"
#include "atm/ServerLink.h"
#include "common/Clock.h"
#include "common/Invariant.h"
#include "crypto/CryptoCore.h"

using gabella_test::check;
using gabella_test::section;

namespace
{
const std::string kAtmId = "ATM-001";

std::filesystem::path tempFile(const std::string& name)
{
    const auto dir = std::filesystem::temp_directory_path() / "gabella-atm-link";
    std::filesystem::create_directories(dir);
    const auto path = dir / name;
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + ".tmp");
    return path;
}

DispenseReport dispenseReport(std::uint64_t seq, DispenseResult result = DispenseResult::Ok)
{
    DispenseReport r;
    r.atmId = kAtmId;
    r.sessionId = "session-" + std::to_string(seq);
    r.sequence = seq;
    r.result = result;
    r.cassetteCounts = { { 100, 50 }, { 200, 50 }, { 500, 49 }, { 1000, 50 } };
    r.timestamp = 1700000000 + static_cast<std::int64_t>(seq);
    return r;
}

PendingReport pendingDispense(std::uint64_t seq)
{
    PendingReport p;
    p.kind = PendingKind::DispenseReport;
    p.dispense = dispenseReport(seq);
    return p;
}

PendingReport pendingResult(std::uint64_t seq, bool ok)
{
    PendingReport p;
    p.kind = PendingKind::CommandResult;
    p.commandSeq = seq;
    p.commandOk = ok;
    return p;
}

PendingReport pendingCheckpoint()
{
    PendingReport p;
    p.kind = PendingKind::Checkpoint;
    p.checkpoint.logId = kAtmId;
    p.checkpoint.seqNo = 42;
    p.checkpoint.hash = std::string(64, 'a');
    p.checkpoint.timestamp = 1700000123;
    p.checkpoint.mac = std::string("mac\0with|odd\nbytes", 18);
    return p;
}

StatusReport statusReport(StatusReason reason)
{
    StatusReport r;
    r.atmId = kAtmId;
    r.reason = reason;
    r.lastExecutedSequence = 3;
    r.cassetteCounts = { { 100, 50 }, { 200, 50 }, { 500, 50 }, { 1000, 50 } };
    r.timestamp = 1700000000;
    return r;
}

struct LinkRig
{
    HsmFixture fx;
    FakeClock clock;
    FakeServerApi api{ *fx.bank, clock };
    PendingReportQueue queue;
    ServerLink link{ api, *fx.atm, queue, clock, kAtmId };
};

void queueTests()
{
    section("PendingReportQueue");

    PendingReportQueue memory;
    check(memory.load() && memory.empty(), "a queue without a file starts empty");
    check(memory.push(pendingDispense(1)) && memory.push(pendingResult(7, true)) && memory.push(pendingCheckpoint()), "reports are accepted in order");
    check(memory.size() == 3 && memory.front().dispense.sequence == 1 && memory.at(1).commandSeq == 7 && memory.at(2).checkpoint.seqNo == 42, "they are kept in the order they arrived");
    check(memory.erase(1) && memory.size() == 2 && memory.at(1).kind == PendingKind::Checkpoint, "a report can be removed from the middle");
    check(memory.pop() && memory.size() == 1 && memory.front().kind == PendingKind::Checkpoint, "the front can be removed");
    check(!memory.erase(5), "removing past the end is refused");

    bool threw = false;
    try
    {
        (void)memory.at(9);
    }
    catch (const InvariantViolation&)
    {
        threw = true;
    }
    check(threw, "reading past the end is an invariant violation");

    const auto path = tempFile("queue.log");
    {
        PendingReportQueue stored(path);
        check(stored.load(), "a missing file loads as an empty queue");
        check(stored.push(pendingDispense(1)) && stored.push(pendingResult(7, false)) && stored.push(pendingCheckpoint()), "reports are written to the file");
    }

    PendingReportQueue restarted(path);
    check(restarted.load() && restarted.size() == 3, "a restart finds everything again");
    if (restarted.size() == 3)
    {
        const DispenseReport original = dispenseReport(1);
        check(restarted.at(0).kind == PendingKind::DispenseReport && restarted.at(0).dispense.payload() == original.payload(), "a dispense report comes back byte for byte, so its MAC still holds");
        check(restarted.at(1).kind == PendingKind::CommandResult && restarted.at(1).commandSeq == 7 && !restarted.at(1).commandOk, "a command result comes back intact");
        check(restarted.at(2).checkpoint.payload() == pendingCheckpoint().checkpoint.payload() && restarted.at(2).checkpoint.mac == pendingCheckpoint().checkpoint.mac,
            "a checkpoint with binary bytes in its MAC comes back intact");
    }
    else
    {
        check(false, "the reports come back intact after a restart");
    }

    check(restarted.erase(0), "a delivered report is removed");
    PendingReportQueue afterErase(path);
    check(afterErase.load() && afterErase.size() == 2 && afterErase.front().kind == PendingKind::CommandResult, "the removal survives a restart");

    {
        std::ofstream out(path, std::ios::app | std::ios::binary);
        out << "not-hex\n"
            << "abcd\n";
    }
    PendingReportQueue damaged(path);
    check(!damaged.load() && damaged.size() == 2 && damaged.skippedOnLoad() == 2, "damaged lines are skipped and counted, the good ones survive");
    check(damaged.pop(), "the file is repaired by the next removal");
    PendingReportQueue repaired(path);
    check(repaired.load() && repaired.size() == 1, "the damaged lines are gone after a rewrite");

    const auto directory = std::filesystem::temp_directory_path() / "gabella-atm-link" / "a-directory";
    std::filesystem::create_directories(directory);
    PendingReportQueue unwritable(directory);
    check(!unwritable.push(pendingDispense(1)), "a push that cannot reach the disk says so");
    check(unwritable.size() == 1, "the report is still kept in memory for this run");
    check(!unwritable.erase(0) && unwritable.size() == 1, "a removal that cannot be recorded keeps the report");
}

void headerTests()
{
    section("Request headers");

    LinkRig r;

    r.link.reportDispense(dispenseReport(1));
    check(r.api.dispenseReports.size() == 1 && r.api.rejectedHeaders == 0, "a dispense report is accepted with a valid header");
    check(r.link.syncStatus(statusReport(StatusReason::Reconnect)) && r.api.statusReports.size() == 1, "a status report is accepted");
    r.link.endSession("session-1");
    r.link.staffLogout("tok-test");
    r.link.reportCommandResult(5, true);
    check(r.api.endedSessions.size() == 1 && r.api.loggedOut.size() == 1 && r.api.commandResults.size() == 1, "session end, logout and command result are accepted");
    check(r.link.pollCommands().empty() && r.api.accepted.back() == "PollCommands", "polling for commands is accepted");
    check(r.api.rejectedHeaders == 0, "no header was ever refused");

    check(r.api.headers.size() >= 6 && r.api.headers[0].nonce != r.api.headers[1].nonce, "every call carries a fresh nonce");
    check(r.api.headers[0].timestamp == r.clock.nowUnix() && r.api.headers[0].atmId == kAtmId, "the header carries the ATM id and the current time");

    r.clock.advance(1000);
    r.link.reportDispense(dispenseReport(2));
    check(r.api.dispenseReports.size() == 2 && r.api.rejectedHeaders == 0, "the time in the header follows the clock");

    StaffLoginRequest login;
    login.atmId = kAtmId;
    login.staffId = "E-01";
    login.nonce = *r.fx.atm->generateNonce();
    login.timestamp = r.clock.nowUnix();
    login.sealedPassword = *r.fx.atm->sealPassword("S3cretPass", login.binding());
    const auto result = r.link.staffLogin(login);
    check(result && result->token == "tok-test" && r.api.logins.size() == 1, "a staff login is accepted");
    check(r.api.headers.back().nonce == login.nonce && r.api.headers.back().timestamp == login.timestamp, "the login header reuses the nonce and time that the password is bound to");

    r.api.latest = Checkpoint{ kAtmId, 9, std::string(64, 'b'), r.clock.nowUnix(), "mac" };
    const std::string nonce = *r.fx.atm->generateNonce();
    const auto reply = r.link.latestCheckpoint("tok-aud", nonce);
    check(reply && reply->requestNonce == nonce && r.api.lastCheckpointNonce == nonce, "the checkpoint request carries the caller's nonce so the answer can be checked for freshness");
    check(reply && r.fx.atm->verifyServer(SignDomain::Checkpoint, reply->signedPayload(), reply->signature), "the signed answer is passed back for the caller to verify");

    AccessRequest ask;
    ask.staffToken = "tok-test";
    ask.action = Action::LoadCash;
    check(r.link.decide(ask).verdict == Verdict::Allowed && r.api.decisions.size() == 1 && r.api.decisions[0].atmId == kAtmId, "an access question gets this ATM's id");
    AccessRequest other = ask;
    other.atmId = "ATM-OTHER";
    const std::size_t before = r.api.received;
    check(r.link.decide(other).verdict == Verdict::Denied && r.api.received == before, "an ATM cannot ask on another ATM's behalf, and the server is not even asked");
}

void authorizeTests()
{
    section("Authorization answers");

    LinkRig r;
    const AuthRequest request("ATM-001", "session-1", Action::CheckBalance, "cipher", "nonce-1", 1700000000, "4111111111111111", 0, "mac");

    const auto good = r.link.authorize(request);
    check(good && good->status == AuthStatus::Approved, "a correctly signed answer is passed on");

    r.api.forgeSignature = true;
    check(!r.link.authorize(request), "an answer with a broken signature is dropped");
    r.api.forgeSignature = false;

    r.api.onAuthorize = [](const AuthRequest&)
    {
        AuthResponse other;
        other.status = AuthStatus::Approved;
        other.sessionId = "somebody-else";
        return other;
    };
    check(!r.link.authorize(request), "a signed answer for another session is dropped");
    r.api.onAuthorize = nullptr;

    r.api.online = false;
    check(!r.link.authorize(request), "the server's unsigned refusal is dropped");
    r.api.online = true;

    r.api.throwOnCall = true;
    check(!r.link.authorize(request), "a server that throws is treated as no answer");
}

void queueingTests()
{
    section("Reports that cannot be sent");

    LinkRig offline;
    offline.api.online = false;
    offline.link.reportDispense(dispenseReport(1));
    check(offline.queue.size() == 1 && offline.api.dispenseReports.empty(), "a report that cannot be sent is queued");
    check(!offline.link.flushPending() && offline.queue.size() == 1, "flushing while the server is away keeps it");
    offline.api.online = true;
    check(offline.link.flushPending() && offline.queue.empty() && offline.api.dispenseReports.size() == 1, "once the server is back the queue is delivered and emptied");

    LinkRig order;
    order.api.online = false;
    order.link.reportDispense(dispenseReport(1));
    order.link.reportDispense(dispenseReport(2));
    order.link.reportCommandResult(9, false);
    order.api.online = true;
    check(order.link.flushPending(), "everything queued is delivered");
    check(order.api.dispenseReports.size() == 2 && order.api.dispenseReports[0].sequence == 1 && order.api.dispenseReports[1].sequence == 2, "dispense reports arrive in the order they happened");
    check(order.api.commandResults.size() == 1 && order.api.commandResults[0].first == 9 && !order.api.commandResults[0].second, "the command result arrives too");

    LinkRig stale;
    stale.api.online = false;
    stale.link.reportDispense(dispenseReport(1));
    stale.clock.advance(600);
    stale.api.online = true;
    check(stale.link.flushPending() && stale.api.rejectedHeaders == 0, "a report queued ten minutes ago is sent with a fresh header and accepted");
    check(stale.api.headers.back().timestamp == stale.clock.nowUnix(), "the header was made at send time, not at queue time");

    LinkRig ordered;
    ordered.api.online = false;
    ordered.link.reportDispense(dispenseReport(1));
    ordered.api.online = true;
    ordered.link.reportDispense(dispenseReport(2));
    check(ordered.queue.empty() && ordered.api.dispenseReports.size() == 2 && ordered.api.dispenseReports[0].sequence == 1, "a new report first lets the waiting ones through");

    LinkRig stuck;
    stuck.api.online = false;
    stuck.link.reportDispense(dispenseReport(1));
    stuck.link.reportCommandResult(4, true);
    check(stuck.queue.size() == 2, "a dispense report and a command result are both waiting");
    stuck.api.online = true;
    stuck.api.refuseDispenseReports = true;
    check(!stuck.link.flushPending(), "flushing reports that something is still waiting");
    check(stuck.queue.size() == 1 && stuck.api.commandResults.size() == 1, "a report the server keeps refusing does not hold back the ones behind it");
    check(stuck.queue.front().kind == PendingKind::DispenseReport, "the refused report stays queued");
    stuck.api.refuseDispenseReports = false;
    check(stuck.link.flushPending() && stuck.api.dispenseReports.size() == 1, "and is delivered as soon as the server takes it");

    LinkRig throwing;
    throwing.api.throwOnCall = true;
    throwing.link.reportDispense(dispenseReport(1));
    check(throwing.queue.size() == 1, "a server that throws does not lose the report");

    const auto path = tempFile("link-queue.log");
    {
        PendingReportQueue persistent(path);
        LinkRig first;
        ServerLink link(first.api, *first.fx.atm, persistent, first.clock, kAtmId);
        first.api.online = false;
        link.reportDispense(dispenseReport(1));
        link.reportCommandResult(3, true);
    }
    PendingReportQueue reloaded(path);
    check(reloaded.load() && reloaded.size() == 2, "queued reports survive a restart");
    LinkRig second;
    ServerLink restarted(second.api, *second.fx.atm, reloaded, second.clock, kAtmId);
    check(restarted.flushPending() && second.api.dispenseReports.size() == 1 && second.api.commandResults.size() == 1, "and are delivered after it");
    PendingReportQueue afterDelivery(path);
    check(afterDelivery.load() && afterDelivery.empty(), "the file is empty once everything is delivered");
}

void statusAndCheckpointTests()
{
    section("Status reports and checkpoints");

    LinkRig r;
    r.api.online = false;
    r.link.reportDispense(dispenseReport(1));
    check(!r.link.syncStatus(statusReport(StatusReason::Reconnect)), "a status report is not accepted while the server is away");
    r.api.online = true;
    check(r.link.syncStatus(statusReport(StatusReason::Reconnect)), "it is accepted once the server is back");
    check(r.api.dispenseReports.size() == 1 && r.queue.empty(), "the waiting dispense report went out first");

    LinkRig cp;
    const PendingReport item = pendingCheckpoint();
    check(cp.link.submit(item.checkpoint) && cp.api.checkpoints.size() == 1, "a checkpoint is delivered");
    cp.api.online = false;
    check(cp.link.submit(item.checkpoint) && cp.queue.size() == 1 && cp.queue.front().kind == PendingKind::Checkpoint, "a checkpoint that cannot be delivered is taken into the queue");
    cp.api.online = true;
    check(cp.link.flushPending() && cp.api.checkpoints.size() == 2, "and delivered later");

    LinkRig best;
    best.api.online = false;
    best.link.endSession("s");
    best.link.staffLogout("t");
    check(best.queue.empty(), "ending a session or logging out is not queued");
}

void wipedKeysTests()
{
    section("After the keys are wiped");

    LinkRig r;
    r.fx.atm->reportTamper();
    r.link.reportDispense(dispenseReport(1));
    check(r.queue.size() == 1 && r.api.received == 0, "without keys nothing can be authenticated, so reports wait");
    check(!r.link.syncStatus(statusReport(StatusReason::Reconnect)), "status reports are refused");
    check(r.link.pollCommands().empty(), "no commands are fetched");
    AccessRequest ask;
    ask.staffToken = "tok";
    ask.action = Action::LoadCash;
    check(r.link.decide(ask).verdict == Verdict::Denied, "no access decisions are made");
    StaffLoginRequest login;
    login.atmId = kAtmId;
    login.staffId = "E-01";
    login.nonce = "n";
    login.timestamp = r.clock.nowUnix();
    check(!r.link.staffLogin(login), "no staff login is possible");
    check(r.link.submit(pendingCheckpoint().checkpoint) && r.queue.size() == 2, "checkpoints wait in the queue");
}

void tamperTests()
{
    section("Tamper report");

    LinkRig before;
    before.link.reportTamper();
    check(before.api.tamperSeen && before.api.tamperAuthenticated, "a tamper report sent while the keys exist is authenticated");

    LinkRig after;
    after.fx.atm->reportTamper();
    after.link.reportTamper();
    check(after.api.tamperSeen && !after.api.tamperAuthenticated, "after the wipe the report goes out without a MAC");

    LinkRig refused;
    refused.fx.atm->reportTamper();
    refused.api.acceptUnauthenticatedTamper = false;
    refused.link.reportTamper();
    check(!refused.api.tamperSeen, "a server that insists on a MAC does not take it");
    refused.api.acceptUnauthenticatedTamper = true;
    check(refused.link.flushPending() && refused.api.tamperSeen, "the report is repeated with the next flush");
    check(refused.queue.empty(), "and never enters the report queue");

    LinkRig offline;
    offline.api.online = false;
    offline.link.reportTamper();
    offline.api.online = true;
    check(offline.link.flushPending() && offline.api.tamperSeen, "a tamper report sent while the server was away is repeated later");
}
}

int main()
{
    gabella_test::banner("ATM server link test suite");
    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return 1;
    }

    queueTests();
    headerTests();
    authorizeTests();
    queueingTests();
    statusAndCheckpointTests();
    wipedKeysTests();
    tamperTests();

    return gabella_test::summary();
}

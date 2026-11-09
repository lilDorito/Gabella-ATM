#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

#include "Check.h"
#include "ServerRig.h"
#include "server/db/DbError.h"
#include "server/db/Schema.h"
#include "server/db/Statement.h"
#include "server/db/Transaction.h"

using gabella_test::check;
using gabella_test::section;

namespace
{
template <typename F>
bool rejected(F&& f)
{
    try
    {
        f();
        return false;
    }
    catch (const DbError&)
    {
        return true;
    }
}

std::filesystem::path tempDb(const std::string& name)
{
    const auto dir = std::filesystem::temp_directory_path() / "gabella-server-core";
    std::filesystem::create_directories(dir);
    const auto path = dir / name;
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
    return path;
}

void seedAccount(Database& db, const std::string& id, std::int64_t balance)
{
    Statement s(db, "INSERT INTO accounts (account_id, owner_name, balance_kop) VALUES (?, 'Owner', ?)");
    s.bind(1, id).bind(2, balance).run();
}

void seedTransaction(Database& db, std::int64_t seq)
{
    Statement s(db, "INSERT INTO transactions (atm_id, session_id, account_id, amount_kop, dispense_seq, status, created_at) VALUES ('ATM-001', 's', 'ACC-1', 50000, ?, 'HELD', 1)");
    s.bind(1, seq).run();
}

void setTxStatus(Database& db, std::int64_t seq, const std::string& status)
{
    Statement s(db, "UPDATE transactions SET status = ? WHERE dispense_seq = ?");
    s.bind(1, status).bind(2, seq).run();
}

void insertRequest(Database& db, const std::string& id, std::int64_t approvals)
{
    Statement s(db, "INSERT INTO dual_control_requests VALUES (?, 'RestoreFromOutOfService', 'ATM-001', 'A-01', ?, 1, 2, 'PENDING')");
    s.bind(1, id).bind(2, approvals).run();
}

void databaseTests()
{
    section("Database, schema and transactions");

    ServerRig r;
    check(r.db.schemaVersion() == kSchemaVersion, "a new database gets the current schema version");

    const auto file = tempDb("bank.db");
    {
        Database first(file.string());
        seedAccount(first, "ACC-1", 100);
    }
    {
        Database again(file.string());
        Statement s(again, "SELECT balance_kop FROM accounts WHERE account_id = 'ACC-1'");
        check(s.step() && s.columnInt64(0) == 100, "reopening keeps the data and does not reinstall the schema");
        again.exec("UPDATE schema_version SET version = 99");
    }
    check(rejected([&] { Database wrong(file.string()); }), "a database with another schema version is refused at startup");

    const auto missing = tempDb("missing.db");
    check(rejected([&] { Database readOnly(missing.string(), OpenMode::ReadOnly); }), "read-only mode does not create a missing database");
    check(!std::filesystem::exists(missing), "nothing is written in read-only mode");

    seedAccount(r.db, "ACC-1", 100000);
    {
        Transaction tx(r.db);
        Statement s(r.db, "UPDATE accounts SET balance_kop = 0 WHERE account_id = 'ACC-1'");
        s.run();
    }
    Statement balance(r.db, "SELECT balance_kop FROM accounts WHERE account_id = 'ACC-1'");
    check(balance.step() && balance.columnInt64(0) == 100000, "a transaction without commit is rolled back");
    balance.reset();
    {
        Transaction tx(r.db);
        Statement s(r.db, "UPDATE accounts SET balance_kop = 90000 WHERE account_id = 'ACC-1'");
        s.run();
        tx.commit();
    }
    check(balance.step() && balance.columnInt64(0) == 90000, "a committed transaction persists");

    const std::string injection = "x'); DROP TABLE accounts; --";
    seedAccount(r.db, injection, 1);
    Statement survived(r.db, "SELECT count(*) FROM accounts");
    check(survived.step() && survived.columnInt64(0) == 2, "bound parameters are stored literally, never executed");
}

void constraintTests()
{
    section("Protections inside the database");

    ServerRig r;
    seedAccount(r.db, "ACC-1", 100000);

    check(rejected([&] { seedAccount(r.db, "ACC-2", -1); }), "a balance cannot go negative");
    check(rejected([&] { r.db.exec("INSERT INTO cards (pan, account_id, exp_month, exp_year, pin_verify_value, status) VALUES ('4111', 'NOPE', 1, 2030, 'v', 'ACTIVE')"); }),
        "foreign keys are enforced");
    check(rejected([&] { r.db.exec("INSERT INTO staff (staff_id, role, password_hash, status) VALUES ('E-01', 'ServiceEngineer', 'hunter2', 'ACTIVE')"); }), "a plain password cannot be stored");
    check(rejected([&] { r.db.exec("INSERT INTO staff (staff_id, role, password_hash, status) VALUES ('C-01', 'Client', '$argon2id$v=19$x', 'ACTIVE')"); }), "staff roles exclude clients");

    seedTransaction(r.db, 1);
    check(rejected([&] { seedTransaction(r.db, 1); }), "one dispense command cannot be booked twice");
    check(rejected([&] { r.db.exec("UPDATE transactions SET amount_kop = 1 WHERE dispense_seq = 1"); }), "a transaction's amount is fixed");
    setTxStatus(r.db, 1, "UNCERTAIN");
    setTxStatus(r.db, 1, "COMMITTED");
    check(rejected([&] { setTxStatus(r.db, 1, "HELD"); }), "a committed transaction cannot go back to HELD");
    check(rejected([&] { setTxStatus(r.db, 1, "REVERSED"); }), "a committed transaction cannot be reversed afterwards");
    check(rejected([&] { setTxStatus(r.db, 1, "COMMITTED"); }), "a transaction cannot be committed twice");

    insertRequest(r.db, "DC-1", 2);
    check(rejected([&] { insertRequest(r.db, "DC-2", 1); }), "a dual control threshold below 2 is refused");
    r.db.exec("INSERT INTO dual_control_approvals (request_id, staff_id, approved_at) VALUES ('DC-1', 'A-01', 1)");
    check(rejected([&] { r.db.exec("INSERT INTO dual_control_approvals (request_id, staff_id, approved_at) VALUES ('DC-1', 'A-01', 2)"); }), "one person cannot approve twice");
    check(rejected([&] { r.db.exec("UPDATE dual_control_requests SET required_approvals = 5 WHERE request_id = 'DC-1'"); }), "a request's threshold cannot be changed later");
    r.db.exec("UPDATE dual_control_requests SET status = 'APPROVED' WHERE request_id = 'DC-1'");
    r.db.exec("UPDATE dual_control_requests SET expires_at = 99 WHERE request_id = 'DC-1'");
    check(rejected([&] { r.db.exec("UPDATE dual_control_requests SET status = 'PENDING' WHERE request_id = 'DC-1'"); }), "dual control status only moves forward");
}

void repositoryTests()
{
    section("ATM and nonce repositories");

    ServerRig r;
    const auto atm = r.atms.find(kRigAtm);
    check(atm && atm->status == AtmStatus::Active && !atm->logReviewRequired, "a registered ATM starts active");
    check(!r.atms.find("ATM-404"), "an unknown ATM is not found");
    check(rejected([&] { r.atms.insert(kRigAtm); }), "an ATM cannot be registered twice");
    check(rejected([&] { r.atms.insert(kServerLogId); }), "the server log's id cannot be used for an ATM");
    check(r.atms.setStatus(kRigAtm, AtmStatus::OutOfService) && r.atms.find(kRigAtm)->status == AtmStatus::OutOfService, "status changes are stored");
    check(r.atms.flagLogReview(kRigAtm) && r.atms.find(kRigAtm)->logReviewRequired, "an ATM can be flagged for log review");
    check(!r.atms.setStatus("ATM-404", AtmStatus::Active), "changing an unknown ATM reports false");

    check(r.nonces.insertIfNew("n1", kRigAtm, 100), "a new nonce is accepted");
    check(!r.nonces.insertIfNew("n1", kRigAtm, 101), "a repeated nonce is refused");
    r.nonces.purgeOlderThan(101);
    check(r.nonces.insertIfNew("n1", kRigAtm, 200), "purged nonces are forgotten");
}

void gateTests()
{
    section("Request gate");

    ServerRig r;
    const std::string body = ApiBody::endSession("S-1");
    check(r.gate.admit(ApiCall::EndSession, r.header(ApiCall::EndSession, body), body, false) == GateVerdict::Admitted, "a correct request is admitted");

    const RequestHeader replayed = r.header(ApiCall::EndSession, body);
    (void)r.gate.admit(ApiCall::EndSession, replayed, body, false);
    check(r.gate.admit(ApiCall::EndSession, replayed, body, false) == GateVerdict::ReplayedNonce, "a replayed request is refused");
    check(r.count(EventType::NONCE_REPLAY) == 1, "the replay is logged as NONCE_REPLAY");

    check(r.gate.admit(ApiCall::EndSession, r.header(ApiCall::EndSession, body), ApiBody::endSession("S-2"), false) == GateVerdict::BadMac, "a changed body breaks the MAC");
    check(r.gate.admit(ApiCall::StaffLogout, r.header(ApiCall::EndSession, body), body, false) == GateVerdict::BadMac, "a MAC for one call is not valid for another");

    RequestHeader forged = r.header(ApiCall::EndSession, body);
    forged.mac[0] = static_cast<char>(forged.mac[0] ^ 1);
    check(r.gate.admit(ApiCall::EndSession, forged, body, false) == GateVerdict::BadMac, "a forged MAC is refused");

    RequestHeader old = r.header(ApiCall::EndSession, body);
    r.clock.advance(61);
    check(r.gate.admit(ApiCall::EndSession, old, body, false) == GateVerdict::StaleRequest, "a request older than 60 seconds is refused");
    RequestHeader early = r.header(ApiCall::EndSession, body);
    early.timestamp += 120;
    early.mac = *r.fx.atm->macMessage(early.macPayload(ApiCall::EndSession, body));
    check(r.gate.admit(ApiCall::EndSession, early, body, false) == GateVerdict::StaleRequest, "a request from the future is refused");

    RequestHeader blank = r.header(ApiCall::EndSession, body);
    blank.nonce.clear();
    blank.mac = *r.fx.atm->macMessage(blank.macPayload(ApiCall::EndSession, body));
    check(r.gate.admit(ApiCall::EndSession, blank, body, false) == GateVerdict::ReplayedNonce, "a request without a nonce is refused");

    check(r.gate.admit(ApiCall::EndSession, r.header(ApiCall::EndSession, body, "ATM-404"), body, false) == GateVerdict::UnknownAtm, "an unknown ATM is refused");
    check(r.count(EventType::ACCESS_DENIED) >= 5, "refusals are logged");

    (void)r.atms.setStatus(kRigAtm, AtmStatus::OutOfService);
    check(r.gate.admit(ApiCall::EndSession, r.header(ApiCall::EndSession, body), body, false) == GateVerdict::AtmOutOfService, "an out-of-service ATM is refused where service is required");
    check(r.gate.admit(ApiCall::EndSession, r.header(ApiCall::EndSession, body), body, true) == GateVerdict::Admitted, "an out-of-service ATM can still report and receive commands");
}

class StubAuthorization final : public IAuthorizationService
{
public:
    bool fail = false;

    AuthResponse authorize(const AuthRequest& request) override
    {
        if (fail) throw std::runtime_error("boom");
        AuthResponse r;
        r.status = AuthStatus::Approved;
        r.sessionId = request.getSessionId();
        r.balance = Money::fromKop(123400);
        return r;
    }

    bool endSession(const std::string&, const std::string&) override
    {
        if (fail) throw DbError(1, "disk full");
        return true;
    }
};

AuthRequest makeRequest(ServerRig& r, const std::string& nonce)
{
    const AuthRequest draft(kRigAtm, "S-1", Action::CheckBalance, "ct", nonce, r.clock.nowUnix(), "4111111111111111", 0, "");
    const auto mac = r.fx.atm->macMessage(draft.macPayload());
    return AuthRequest(kRigAtm, "S-1", Action::CheckBalance, "ct", nonce, r.clock.nowUnix(), "4111111111111111", 0, *mac);
}

void facadeTests()
{
    section("BankServer facade");

    ServerRig r;
    const AuthResponse none = r.server.authorize(makeRequest(r, "auth-nonce-0001"));
    check(none.status == AuthStatus::Error, "services that are not built yet answer Error");
    check(r.server.decide(r.header(ApiCall::Decide, AccessRequest{ kRigAtm, "", "tok", Action::LoadCash, "" }.payload()), AccessRequest{ kRigAtm, "", "tok", Action::LoadCash, "" }).verdict
            == Verdict::Denied,
        "an unbuilt decider denies");

    StubAuthorization stub;
    ServerParts parts{ stub, r.unavailable, r.unavailable, r.unavailable, r.unavailable };
    BankServer server(*r.fx.bank, r.log, r.gate, r.atms, r.checkpointService, parts);

    const AuthResponse ok = server.authorize(makeRequest(r, "auth-nonce-0002"));
    check(ok.status == AuthStatus::Approved && r.fx.atm->verifyServer(SignDomain::Response, ok.signedPayload(), ok.signature), "the facade signs every answer");
    check(server.authorize(makeRequest(r, "auth-nonce-0002")).status == AuthStatus::Error, "a replayed authorization never reaches the service");

    AccessRequest otherAtm{ "ATM-002", "", "tok", Action::LoadCash, "" };
    check(server.decide(r.header(ApiCall::Decide, otherAtm.payload()), otherAtm).verdict == Verdict::Denied, "a body naming another ATM than the envelope is refused");

    stub.fail = true;
    bool escaped = false;
    AuthResponse failed;
    bool ended = true;
    try
    {
        failed = server.authorize(makeRequest(r, "auth-nonce-0003"));
        ended = server.endSession(r.header(ApiCall::EndSession, ApiBody::endSession("S-1")), "S-1");
    }
    catch (...)
    {
        escaped = true;
    }
    check(!escaped, "no exception leaves the server");
    check(failed.status == AuthStatus::Error && failed.signature.empty() && !ended, "an internal error becomes an unsigned Error or a refusal");
    check(r.count(EventType::AUTH_DECISION) == 2, "internal errors are logged");

    check(server.reportTamper(r.header(ApiCall::ReportTamper, ApiBody::empty())), "a tamper report is accepted");
    check(r.atms.find(kRigAtm)->status == AtmStatus::OutOfService && r.count(EventType::TAMPER_DETECTED) == 1, "the ATM is taken out of service and the event is logged");
    stub.fail = false;
    check(server.authorize(makeRequest(r, "auth-nonce-0004")).status == AuthStatus::Error, "an ATM reported as tampered gets no more authorizations");
    check(server.pollCommands(r.header(ApiCall::PollCommands, ApiBody::empty())).empty(), "it can still poll for recovery commands");
}
}

int main()
{
    gabella_test::banner("Server core test suite");
    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return 1;
    }

    databaseTests();
    constraintTests();
    repositoryTests();
    gateTests();
    facadeTests();

    return gabella_test::summary();
}

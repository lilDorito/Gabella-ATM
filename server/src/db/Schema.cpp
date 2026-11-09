#include "server/db/Schema.h"

const char* schemaSql()
{
    return R"SQL(
CREATE TABLE schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,
    owner_name TEXT NOT NULL,
    balance_kop INTEGER NOT NULL CHECK (balance_kop >= 0)
);

CREATE TABLE cards (
    pan TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (account_id),
    exp_month INTEGER NOT NULL CHECK (exp_month BETWEEN 1 AND 12),
    exp_year INTEGER NOT NULL,
    pin_verify_value TEXT NOT NULL,
    failed_pin_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_pin_attempts >= 0),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'BLOCKED'))
);

CREATE TABLE staff (
    staff_id TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('ServiceEngineer', 'CashCollector', 'Auditor', 'Admin')),
    password_hash TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    failed_logins INTEGER NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
    locked_until INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED'))
);

CREATE TABLE atms (
    atm_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'OUT_OF_SERVICE')),
    last_dispense_seq INTEGER NOT NULL DEFAULT 0 CHECK (last_dispense_seq >= 0),
    last_command_seq INTEGER NOT NULL DEFAULT 0 CHECK (last_command_seq >= 0),
    log_review_required INTEGER NOT NULL DEFAULT 0 CHECK (log_review_required IN (0, 1))
);

CREATE TABLE atm_cassettes (
    atm_id TEXT NOT NULL REFERENCES atms (atm_id),
    denomination INTEGER NOT NULL CHECK (denomination IN (100, 200, 500, 1000)),
    expected_count INTEGER NOT NULL CHECK (expected_count >= 0),
    PRIMARY KEY (atm_id, denomination)
);

CREATE TABLE transactions (
    tx_id INTEGER PRIMARY KEY AUTOINCREMENT,
    atm_id TEXT NOT NULL REFERENCES atms (atm_id),
    session_id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (account_id),
    amount_kop INTEGER NOT NULL CHECK (amount_kop > 0),
    dispense_seq INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('HELD', 'UNCERTAIN', 'COMMITTED', 'REVERSED')),
    created_at INTEGER NOT NULL,
    resolved_at INTEGER,
    resolved_by TEXT,
    reason TEXT,
    UNIQUE (atm_id, dispense_seq)
);

CREATE TRIGGER transactions_status_forward BEFORE UPDATE OF status ON transactions
WHEN NOT ((OLD.status = 'HELD' AND NEW.status IN ('UNCERTAIN', 'COMMITTED', 'REVERSED'))
       OR (OLD.status = 'UNCERTAIN' AND NEW.status IN ('COMMITTED', 'REVERSED')))
BEGIN
    SELECT RAISE(ABORT, 'transaction status only moves forward');
END;

CREATE TRIGGER transactions_money_fixed BEFORE UPDATE OF atm_id, account_id, amount_kop, dispense_seq ON transactions
BEGIN
    SELECT RAISE(ABORT, 'transaction amounts and parties are fixed');
END;

CREATE TABLE seen_nonces (
    nonce TEXT PRIMARY KEY,
    atm_id TEXT NOT NULL,
    received_at INTEGER NOT NULL
);

CREATE TABLE dual_control_requests (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    params TEXT NOT NULL,
    initiator_id TEXT NOT NULL,
    required_approvals INTEGER NOT NULL CHECK (required_approvals >= 2),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'EXECUTED', 'EXPIRED'))
);

CREATE TRIGGER dual_control_status_forward BEFORE UPDATE OF status ON dual_control_requests
WHEN NOT ((OLD.status = 'PENDING' AND NEW.status IN ('APPROVED', 'EXPIRED'))
       OR (OLD.status = 'APPROVED' AND NEW.status IN ('EXECUTED', 'EXPIRED')))
BEGIN
    SELECT RAISE(ABORT, 'dual control status only moves forward');
END;

CREATE TRIGGER dual_control_terms_fixed BEFORE UPDATE OF action, params, initiator_id, required_approvals, created_at ON dual_control_requests
BEGIN
    SELECT RAISE(ABORT, 'dual control request terms are fixed');
END;

CREATE TABLE dual_control_approvals (
    request_id TEXT NOT NULL REFERENCES dual_control_requests (request_id),
    staff_id TEXT NOT NULL,
    approved_at INTEGER NOT NULL,
    PRIMARY KEY (request_id, staff_id)
);

CREATE TABLE atm_commands (
    atm_id TEXT NOT NULL REFERENCES atms (atm_id),
    command_seq INTEGER NOT NULL CHECK (command_seq > 0),
    action TEXT NOT NULL,
    params TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    signature TEXT NOT NULL,
    request_id TEXT REFERENCES dual_control_requests (request_id),
    status TEXT NOT NULL CHECK (status IN ('QUEUED', 'SUCCEEDED', 'FAILED')),
    PRIMARY KEY (atm_id, command_seq)
);

CREATE TABLE atm_checkpoints (
    log_id TEXT NOT NULL,
    seq_no INTEGER NOT NULL CHECK (seq_no > 0),
    hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    mac TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (log_id, seq_no)
);

CREATE TRIGGER atm_checkpoints_no_update BEFORE UPDATE ON atm_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'checkpoints are append-only');
END;

CREATE TRIGGER atm_checkpoints_no_delete BEFORE DELETE ON atm_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'checkpoints are append-only');
END;
)SQL";
}

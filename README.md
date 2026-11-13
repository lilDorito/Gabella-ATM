# Gabella Bank

A C++17 model of an ATM and the bank behind it, built around one rule: **the server decides, the ATM executes**.

The experiment asks what an ATM looks like if you assume its own software can be compromised. Nothing on the ATM is trusted to make a money decision. It collects input, asks the server, and carries out only answers the server has signed. The hardware is emulated in code, so every attack in the threat model can be run as a test.

> **Status:** complete. The ATM and the bank server run together in one program, every module is tested on its own, and the whole system is tested end to end.

## 1. How it works

**A withdrawal**, end to end:

1. The card reader reads the card. The ATM rejects expired cards and card numbers that fail the Luhn check before talking to anyone.
2. The client picks an amount (a multiple of 100, at most 10,000 UAH) and enters the PIN.
3. The ATM's HSM turns the PIN into an ISO 9564 format 0 block and encrypts it with AES-GCM. The encryption is bound to this exact request (ATM, session, card, amount, nonce, time), so the ciphertext is useless anywhere else. The request is then MACed.
4. The server checks the MAC, the nonce and the PIN, reserves the money and replies with an Ed25519-signed answer. A withdrawal answer carries a signed dispense command with a sequence number and a 60-second lifetime. Reserved money is no longer available, but it leaves the account only when the dispense is confirmed.
5. The dispenser checks that command **itself**: signature, ATM ID, expiry, then the sequence number, which it stores so it survives restarts. Only then does it pay out.
6. Every step is written to a hash-chained audit log first. If the log cannot write, the ATM goes out of service instead of continuing.
7. The ATM reports the result with its cassette counts. The server commits the transaction if the notes are gone and reverses it if they are not. With no report within 2 minutes the transaction becomes uncertain and the money stays reserved until the ATM reconnects and its counters settle it. Until then the ATM gets no new withdrawals. After 24 hours an unsettled transaction is listed in the admin console, and two admins decide it, with a reason.

**Staff** sign in at the ATM's service menu. The password is sealed to the server's public key, bound to that login attempt, and the server returns a short-lived token. Each menu action is then checked with the server:

| Role | Can do |
|---|---|
| Service engineer | load cassettes, run diagnostics |
| Cash collector | collect cash |
| Auditor | verify the ATM's log, read entries |
| Admin | approve critical actions, on the admin console only |

**Critical actions** (installing or rotating keys, returning an ATM to service, resolving a disputed transaction) need dual control: an admin opens a request, and ⌈2n/3⌉ of the n active admins must approve it within 30 minutes. Approval opens a 30-minute window in which the server sends the ATM a signed command; after that the request expires.

**Tamper.** If the case is opened, the HSM wipes its keys, the card is retained, the dispenser locks and the ATM goes out of service. It tells the server, which accepts that one report without a MAC because it can only make things stricter. Recovery takes an on-site key ceremony, new working keys delivered as signed commands, and a signed restore, each under dual control.

## 2. Modules

Each module is its own library, `Gabella::<module>`, and the build enforces the dependency direction.

| Module | Directory | Responsibility | Depends on |
|---|---|---|---|
| Common | `common/` | Shared types: `Money`, `Card`, `Action`, `Role`, `LogEvent`, `AuthRequest`, server messages, canonical encoding, invariants | – |
| Crypto | `crypto/` | `AtmHsm` and `BankHsm` emulators, PIN blocks, key wrapping, signature domains, OpenSSL and libsodium wrappers | common |
| Audit | `audit/` | `AuditLogger`, hash-chained log format, checkpoints and anchors, `LogVerifier`, data policy | common, crypto |
| Access | `access/` | Permissions, staff tokens and login, dual control, the ATM-side `AccessClient` | common, audit |
| ATM | `atm/` | `AtmController`, the session state machine, emulated hardware, attack scenarios, `ServerLink` and the queue of reports waiting to be sent | all of the above |
| Server API | `server_api/` | `IServerApi`, the one interface the bank exposes to ATMs | common |
| Server | `server/`, `tools/` | `BankServer` facade, SQLite database and repositories, `RequestGate`, authorization, reconciliation, staff login, access decisions, dual control, signed commands, checkpoints, `AdminConsole`; the `verify_log` and `seed_db` tools | all of the above except atm |

`app/` puts it all together: a bank with its database and log, and ATM-001 talking to it through `ServerLink`.

## 3. Interfaces

The modules meet through a handful of narrow interfaces, which is also what makes every part testable on its own.

- **Hardware:** `ICardReader`, `IKeypad`, `IDisplay`, `IDispenser`, `ITamperSensor`. The emulators implement them; real devices would too.
- **ATM to bank:** `IServerLink` is the only way the ATM reaches the server.

  ```cpp
  std::optional<AuthResponse> authorize(const AuthRequest& request);
  std::vector<SignedCommand> pollCommands();
  bool syncStatus(const StatusReport& report);
  std::optional<StaffLoginResult> staffLogin(const StaffLoginRequest& request);
  ```

- **Bank API:** `IServerApi` is what the server offers. Every call except authorization (which carries its own MAC) comes with a `RequestHeader`: ATM ID, a single-use nonce, a timestamp and a MAC bound to the call and its body. `RequestGate` checks all four before any service sees the request, and `BankServer` turns any internal failure into a refusal instead of an exception.
- **Access:** `IAccessClient` asks the server whether a staff token may perform an action; `IAccessDecider` is the server-side answer.
- **Audit:** modules write events only through `IAuditSink::record()`. A `false` result means the event was not stored, and a critical action must not go ahead.
- **Storage:** `ICounterStore`, `IDualControlRepository`, `IStaffAuthenticator`, `ICheckpointSink`. In-memory versions back the tests; counters and logs also have file-backed versions, and the server keeps everything else in SQLite.

Every signed or MACed message has exactly one definition of its bytes (`signedPayload()`, `macPayload()`, `pinBinding()`), built with a length-prefixed canonical encoding, so the ATM and the server cannot disagree about what was signed.

## 4. Security mechanisms

- **Keys stay in the HSM.** The ATM software never sees a key, only operations on it. Working keys arrive wrapped under the master key with an integrity tag, so a damaged or swapped key blob is rejected and the old key keeps working. The bank HSM holds a separate key set for every ATM, so one compromised ATM exposes no other.
- **Signatures are domain-separated.** Answers, dispense commands and service commands are signed under different tags, so one can never be passed off as another.
- **No replays.** Request nonces are single-use. Dispense and service commands carry sequence numbers that are stored before they are executed, and both expire.
- **Captured secrets don't travel.** PIN ciphertexts and sealed passwords are bound to the request they were made for.
- **Tamper-evident logs.** Each entry stores the SHA-256 of the previous one. Every 50 entries and at the end of each session, a checkpoint MACed with the audit key leaves the ATM, so truncation and full rewrites are caught as well as edits. A write interrupted by a crash is detected and recorded on the next start.
- **The server remembers.** Checkpoints are stored append-only. A checkpoint that contradicts one already stored is recorded as a rollback and the ATM is flagged for review. An auditor at the ATM gets the latest checkpoint signed by the server, with the request's nonce echoed, so an old answer cannot be replayed.
- **Intent before effect.** Server actions are logged as an intent before the database changes and as a result after, under one operation ID. After a crash, open intents are checked against the database and closed.
- **Nothing sensitive is logged.** PINs, passwords and keys never reach the log, card numbers are masked, and the data policy rejects anything that looks like a full card number.
- **Fail closed.** If a counter cannot be stored, a log cannot be written or cassette counts cannot be confirmed, the ATM refuses to act rather than guess.

## 5. Tests

Thirteen test programs, run by `ctest`:

| Suite | Checks | Covers |
|---|---|---|
| `test_crypto` | 210 | primitives, PIN blocks, HSM lifecycle, key wrapping and rotation, MACs, signatures, sealed boxes, tamper and recovery |
| `test_audit` | 114 | entry format, hash chain, checkpoints, write failures, restarts and torn writes, tampering, file storage, concurrent writers, open intents |
| `test_atm` | 226 | session state machine, dispenser, withdrawals end to end, fail-closed paths, tamper and recovery, signed commands, service and auditor menus |
| `test_access` | 127 | permissions, approval thresholds, tokens, login, dual control end to end |
| `test_server_core` | 61 | schema and its protections, transactions, repositories, request gate, facade error handling, tamper reports |
| `test_server_audit` | 57 | server log, checkpoint acceptance, rollback detection, signed checkpoint replies, crash recovery |
| `test_server_auth` | 89 | PIN checks and lockout, reservations, limits, races, crash recovery |
| `test_seed_db` | 14 | the demo data works against the real services |
| `test_link` | 77 | `ServerLink` and the pending report queue: outages, retries, restarts |
| `test_reconciliation` | 93 | commit, reversal and uncertain transactions, cassette counts, cash loading and collection |
| `test_link_integration` | 36 | the real link against the real server |
| `test_staff_access` | 188 | staff login, access decisions, dual control in SQLite, signed commands, key rotation, admin console, disputed transactions |
| `test_server_flow` | 42 | money end to end: every withdrawal is paid exactly once, failures cost nothing, one open withdrawal per ATM, client sessions |

A good share of them are **attack tests**: jackpotting through the service port, a card skimmer, skipping a step in the session, replaying commands after a restart, holding back a dispense command, moving a captured PIN or password into a new request, and editing, truncating or rewriting the log. Each one has to end in a refusal.

The `sanitize` preset runs everything under AddressSanitizer and UndefinedBehaviorSanitizer.

A log can also be checked by hand, optionally against the checkpoints stored in the bank database:

```bash
./build/debug/tools/verify_log gabella-data/logs/ATM-001.log --db gabella-data/bank.db --log-id ATM-001
```

It exits with 0 for an intact log, 1 for damage and 2 for a usage or read error.

## 6. Running it

`gabella_bank` keeps its database, logs and ATM state in one folder (`gabella-data` by default, or `--data <dir>`). The first start fills the database with demo cards, staff and ATMs; delete the folder to start over.

| Mode | What it does |
|---|---|
| `gabella_bank` or `gabella_bank demo` | a withdrawal, a balance check and a log audit run end to end, then the results are checked |
| `gabella_bank atm` | drive ATM-001 by hand: `card 1` inserts a demo card (or `card <pan> <mm> <yyyy>` any card), then `service`, `commands`, `tamper`, `status`, `help` |
| `gabella_bank admin` | the administrator console: list ATMs, open and approve dual-control requests, resolve disputed transactions |

In a terminal the ATM draws framed screens with colour (set `NO_COLOR` to turn colour off), and the PIN and password are hidden as you type. On every start the server verifies its log and closes any operation that a crash left half done. The demo cards and staff are listed by `help` in ATM mode; every staff password is `S3cretPass`.

A full recovery, for example: `tamper` in ATM mode, then in the admin console `login A-01 S3cretPass`, `request RestoreFromOutOfService ATM-001`, `logout`, `login A-02 S3cretPass`, `approve <id>`, and back in ATM mode `commands`.

## 7. Building

Requirements: CMake 3.20+, a C++17 compiler, OpenSSL 3, libsodium and SQLite 3.

**Linux / macOS**, with system packages (on Debian or Ubuntu: `build-essential cmake pkg-config libssl-dev libsodium-dev libsqlite3-dev`):

```bash
cmake --preset debug
cmake --build build/debug -j
ctest --test-dir build/debug --output-on-failure
./build/debug/app/gabella_bank
```

**Windows / Visual Studio 2022:** set `VCPKG_ROOT`, open the folder and pick the `vcpkg-debug` preset. Dependencies come from `vcpkg.json`.

```bash
cmake --preset vcpkg-debug
cmake --build build/vcpkg-debug
ctest --test-dir build/vcpkg-debug -C Debug
```

| Preset | Build |
|---|---|
| `debug`, `release` | system packages |
| `sanitize` | Debug with ASan and UBSan |
| `vcpkg-debug`, `vcpkg-release` | dependencies from vcpkg |

GCC and Clang builds use `-Wall -Wextra -Wpedantic` and treat warnings as errors. Machine-specific settings go in `CMakeUserPresets.json`, which git ignores.

## 8. Working on the code

Every module has the same shape:

```
<module>/
  CMakeLists.txt
  include/<module>/*.h    public headers, included as "<module>/Header.h"
  src/*.cpp               sources, picked up automatically
```

- **Adding a class** means adding `include/<module>/X.h` and `src/X.cpp`; nothing else needs registering.
- **Dependencies** are declared once in each module's `CMakeLists.txt`. A module cannot include headers from a module it does not depend on, so the ATM cannot reach into the server.
- **Tests** go in `tests/<module>/` and are registered with `gabella_test(...)` in `tests/CMakeLists.txt`.
- **Formatting** follows `.clang-format`: run `clang-format -i` on the files you touch.

## 9. Limitations

- **One process.** The ATM and the server run side by side and talk through an interface, not a network.
- **Emulated hardware.** The HSM, dispenser and sensors are classes that behave like their real counterparts, not drivers for them.
- **The keypad is not a secure PIN pad.** The ATM software sees the PIN as it is typed, so software that records keystrokes is out of scope.
- **Demo keys.** The bank and ATM keys are derived from fixed demo values so the program can restart without a key ceremony. A real deployment would load them into the HSMs once and never write them down.

## 10. Authors

- DEFORTEX
- lilDorito
- PepticPetrel
- VoGnNk

## 11. License

Released under the [MIT License](LICENSE).

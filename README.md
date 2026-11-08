# Gabella Bank

A C++17 model of an ATM and the bank behind it, built around one rule: **the server decides, the ATM executes**.

The experiment asks what an ATM looks like if you assume its own software can be compromised. Nothing on the ATM is trusted to make a money decision. It collects input, asks the server, and carries out only answers the server has signed. The hardware is emulated in code, so every attack in the threat model can be run as a test.

> **Status:** the ATM, cryptography, audit and access modules are complete and tested. The bank server is in progress; until it lands, the tests play the bank with an in-process fake that uses the real cryptography.

## 1. How it works

**A withdrawal**, end to end:

1. The card reader reads the card. The ATM rejects expired cards and card numbers that fail the Luhn check before talking to anyone.
2. The client picks an amount (a multiple of 100, at most 10,000 UAH) and enters the PIN.
3. The ATM's HSM turns the PIN into an ISO 9564 format 0 block and encrypts it with AES-GCM. The encryption is bound to this exact request (ATM, session, card, amount, nonce, time), so the ciphertext is useless anywhere else. The request is then MACed.
4. The server checks the MAC, the nonce and the PIN, reserves the money and replies with an Ed25519-signed answer. A withdrawal answer carries a signed dispense command with a sequence number and a 60-second lifetime.
5. The dispenser checks that command **itself**: signature, ATM ID, expiry, then the sequence number, which it stores so it survives restarts. Only then does it pay out.
6. Every step is written to a hash-chained audit log first. If the log cannot write, the ATM goes out of service instead of continuing.

**Staff** sign in at the ATM's service menu. The password is sealed to the server's public key, bound to that login attempt, and the server returns a short-lived token. Each menu action is then checked with the server:

| Role | Can do |
|---|---|
| Service engineer | load cassettes, run diagnostics |
| Cash collector | collect cash |
| Auditor | verify the ATM's log, read entries |
| Admin | approve critical actions, on the admin console only |

**Critical actions** (installing or rotating keys, returning an ATM to service, resolving a disputed transaction) need dual control: an admin opens a request, and ⌈2n/3⌉ of the n active admins must approve it within 30 minutes. Approval opens a 30-minute window in which the server sends the ATM a signed command; after that the request expires.

**Tamper.** If the case is opened, the HSM wipes its keys, the card is retained, the dispenser locks and the ATM goes out of service. Recovery takes an on-site key ceremony, new working keys delivered as signed commands, and a signed restore, each under dual control.

## 2. Modules

Each module is its own library, `Gabella::<module>`, and the build enforces the dependency direction.

| Module | Directory | Responsibility | Depends on |
|---|---|---|---|
| Common | `common/` | Shared types: `Money`, `Card`, `Action`, `Role`, `LogEvent`, `AuthRequest`, server messages, canonical encoding, invariants | – |
| Crypto | `crypto/` | `AtmHsm` and `BankHsm` emulators, PIN blocks, key wrapping, signature domains, OpenSSL and libsodium wrappers | common |
| Audit | `audit/` | `AuditLogger`, hash-chained log format, checkpoints and anchors, `LogVerifier`, data policy | common, crypto |
| Access | `access/` | Permissions, staff tokens and login, dual control, the ATM-side `AccessClient` | common, audit |
| ATM | `atm/` | `AtmController`, the session state machine, emulated hardware, attack scenarios | all of the above |
| Server | `server/`, `server_api/`, `tools/` | Bank server, its public API and a database seeding tool | in progress |

`app/` holds a small demo that brings up both HSMs and both audit logs and verifies them.

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

- **Access:** `IAccessClient` asks the server whether a staff token may perform an action; `IAccessDecider` is the server-side answer.
- **Audit:** modules write events only through `IAuditSink::record()`. A `false` result means the event was not stored, and a critical action must not go ahead.
- **Storage:** `ICounterStore`, `IDualControlRepository`, `IStaffAuthenticator`, `ICheckpointSink`. In-memory versions back the tests; counters and logs also have file-backed versions, and the SQLite ones come with the server.

Every signed or MACed message has exactly one definition of its bytes (`signedPayload()`, `macPayload()`, `pinBinding()`), built with a length-prefixed canonical encoding, so the ATM and the server cannot disagree about what was signed.

## 4. Security mechanisms

- **Keys stay in the HSM.** The ATM software never sees a key, only operations on it. Working keys arrive wrapped under the master key with an integrity tag, so a damaged or swapped key blob is rejected and the old key keeps working.
- **Signatures are domain-separated.** Answers, dispense commands and service commands are signed under different tags, so one can never be passed off as another.
- **No replays.** Request nonces are single-use. Dispense and service commands carry sequence numbers that are stored before they are executed, and both expire.
- **Captured secrets don't travel.** PIN ciphertexts and sealed passwords are bound to the request they were made for.
- **Tamper-evident logs.** Each entry stores the SHA-256 of the previous one. Every 50 entries and at the end of each session, a checkpoint MACed with the audit key leaves the ATM, so truncation and full rewrites are caught as well as edits. A write interrupted by a crash is detected and recorded on the next start.
- **Nothing sensitive is logged.** PINs, passwords and keys never reach the log, card numbers are masked, and the data policy rejects anything that looks like a full card number.
- **Fail closed.** If a counter cannot be stored, a log cannot be written or cassette counts cannot be confirmed, the ATM refuses to act rather than guess.

## 5. Tests

Four test programs, run by `ctest`:

| Suite | Checks | Covers |
|---|---|---|
| `test_crypto` | 163 | primitives, PIN blocks, HSM lifecycle, key wrapping and rotation, MACs, signatures, sealed boxes, tamper and recovery |
| `test_audit` | 101 | entry format, hash chain, checkpoints, write failures, restarts and torn writes, tampering, file storage, concurrent writers |
| `test_atm` | 148 | session state machine, dispenser, withdrawals end to end, fail-closed paths, tamper and recovery, signed commands, service and auditor menus |
| `test_access` | 127 | permissions, approval thresholds, tokens, login, dual control end to end |

A good share of them are **attack tests**: jackpotting through the service port, a card skimmer, skipping a step in the session, replaying commands after a restart, holding back a dispense command, moving a captured PIN or password into a new request, and editing, truncating or rewriting the log. Each one has to end in a refusal.

The `sanitize` preset runs everything under AddressSanitizer and UndefinedBehaviorSanitizer.

## 6. Building

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

## 7. Working on the code

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

## 8. Limitations

- **One process.** The ATM and the server run side by side and talk through an interface, not a network.
- **Emulated hardware.** The HSM, dispenser and sensors are classes that behave like their real counterparts, not drivers for them.
- **The keypad is not a secure PIN pad.** The ATM software sees the PIN as it is typed, so software that records keystrokes is out of scope.
- **The server is not finished.** Until it is, its behaviour lives in the test fake, and the SQLite repositories are still to come.

## 9. Authors

- DEFORTEX
- lilDorito
- PepticPetrel
- VoGnNk

## 10. License

Released under the [MIT License](LICENSE).

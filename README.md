# Gabella Bank — ATM + SE

A C++17 model of an ATM and an authoritative bank server, built around one rule: **the server decides, the ATM executes**. Everything on the ATM side is treated as potentially compromised, so every money- or security-relevant decision is made on the server and sent back as an Ed25519-signed answer. The ATM and the server run in one process, but they are separated by a single interface (`IServerApi`), and the build makes it impossible for ATM code to include server headers.

Hardware (card reader, keypad, display, dispenser, HSM) is emulated by classes. The full architecture is described in the T1 specification document.

## Modules

| # | Module | Directory |
|---|--------|-----------|
| 1 | Core & Hardware Emulation | `atm/` |
| 2 | Security Engineering & Cryptography | `crypto/` |
| 3 | Secure Audit & Logging | `audit/` |
| 4 | Access Control & Threat Modeling | `access/` |
| 5 | Bank Server | `server/`, `server_api/`, `tools/` |

Shared types used by every module (`Action`, `Role`, `EventType`, `LogEvent`, `Money`, `IClock`, `Card`, `AuthRequest`, `maskPan`, `ATM_INVARIANT`, …) live in `common/`. `app/main.cpp` wires the system together.

## Layout

Every module follows the same shape and is built as its own library `Gabella::<module>`:

```
<module>/
  CMakeLists.txt
  include/<module>/*.h    public headers, included as "<module>/Header.h"
  src/*.cpp               sources (sub-folders allowed)
```

Sources are picked up automatically, so adding a class is just adding `include/<module>/X.h` and `src/X.cpp`. Dependencies between modules are declared once in each module's `CMakeLists.txt`; `atm` does not link `server`, so `#include "server/..."` from ATM code fails to compile.

Tests live in `tests/<module>/`. Add a test executable with `gabella_test(...)` in `tests/CMakeLists.txt`; it is then run by `ctest`.

## Building

Requirements: CMake 3.20+, a C++17 compiler, OpenSSL 3, libsodium, SQLite3.

**Linux / macOS** (system packages, e.g. `libssl-dev libsodium-dev libsqlite3-dev`):

```
cmake --preset debug
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

**Windows / Visual Studio 2022**: set `VCPKG_ROOT`, open the repository folder (File -> Open -> Folder) and pick the `vcpkg-debug` preset. Dependencies come from `vcpkg.json` automatically. From a terminal:

```
cmake --preset vcpkg-debug
cmake --build build/vcpkg-debug
ctest --test-dir build/vcpkg-debug -C Debug
```

The `sanitize` preset builds with AddressSanitizer and UndefinedBehaviorSanitizer. GCC/Clang builds use `-Wall -Wextra -Wpedantic -Werror`.

## Audit logging in short

Two logs (ATM and server), same code, different files and keys. Each entry stores the SHA-256 of the previous one, so editing, deleting, inserting or reordering entries breaks the chain. Every 50 entries and at the end of each session the logger produces a checkpoint (last sequence number + hash, MACed with `auditKey`) that is sent off the ATM, which catches truncation and full rewrites. Modules write events only through `IAuditSink::record()`; a `false` result means the event was not persisted and a critical action must not proceed. PINs, passwords, keys and full card numbers are never logged — pass PANs through `maskPan()` first.

After replacing the audit working key, call `sealCheckpoint()` so the local anchor is re-MACed with the new key.

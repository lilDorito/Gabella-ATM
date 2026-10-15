// main.cpp — test driver for Module 2.
// Not part of production. Exercises Card, CryptoCore, AtmHsm, BankHsm,
// PinModule, and the ATM <-> server end-to-end flow.

#include <sodium.h>

#include "crypto/AtmHsm.h"
#include "common/AuthRequest.h"
#include "crypto/BankHsm.h"
#include "common/Card.h"
#include "crypto/CryptoCore.h"
#include "crypto/PinBlock.h"
#include "crypto/PinModule.h"
#include "crypto/SignDomain.h"

#include <array>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>

// ---------------------------------------------------------------- test infra

static int g_passed = 0;
static int g_failed = 0;

static void check(bool cond, const std::string& name)
{
    std::cout << (cond ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    if (cond) ++g_passed; else ++g_failed;
}

static void section(const std::string& title)
{
    std::cout << "\n=== " << title << " ===\n";
}

static std::string toHex(const std::string& s)
{
    static const char* H = "0123456789abcdef";
    std::string r;
    for (unsigned char c : s) {
        r.push_back(H[c >> 4]);
        r.push_back(H[c & 0x0F]);
    }
    return r;
}

// ---------------------------------------------------------------- key pairs

struct SignKeyPair {
    std::array<unsigned char, 32> pub;
    std::array<unsigned char, 64> secret;
};

struct BoxKeyPair {
    std::array<unsigned char, 32> pub;
    std::array<unsigned char, 32> secret;
};

static SignKeyPair generateSignKeyPair()
{
    SignKeyPair kp;
    crypto_sign_keypair(kp.pub.data(), kp.secret.data());
    return kp;
}

static BoxKeyPair generateBoxKeyPair()
{
    BoxKeyPair kp;
    crypto_box_keypair(kp.pub.data(), kp.secret.data());
    return kp;
}

// ---------------------------------------------------------------- Card

static void testCard()
{
    section("Card");

    Card card("5432101234567890", 12, 2030);
    check(card.getPan() == "5432101234567890", "getPan returns stored PAN");

    check(!card.isExpired(11, 2030), "isExpired: month before expiry -> valid");
    check(!card.isExpired(12, 2030), "isExpired: expiry month -> still valid");
    check(card.isExpired(1, 2031), "isExpired: month after expiry -> expired");
    check(!card.isExpired(12, 2029), "isExpired: earlier year -> valid");

    Card luhnValid("4539148803436467", 12, 2030);
    Card luhnInvalid("4539148803436468", 12, 2030);
    check(luhnValid.isValidLuhn(), "isValidLuhn: valid PAN");
    check(!luhnInvalid.isValidLuhn(), "isValidLuhn: tampered PAN");

    Card empty("", 12, 2030);
    check(!empty.isValidLuhn(), "isValidLuhn: empty PAN -> false");

    Card nonDigit("abcdefghijklmnop", 12, 2030);
    check(!nonDigit.isValidLuhn(), "isValidLuhn: non-digit PAN -> false");

    Card tooShort("123456789012", 12, 2030);
    check(!tooShort.isValidLuhn(), "isValidLuhn: 12-digit PAN -> false");
}

// ---------------------------------------------------------------- buildPinBlock

static void testPinBlock()
{
    section("buildPinBlock (ISO 9564 Format 0)");

    const unsigned char expected[8] =
    { 0x04, 0x12, 0x15, 0xFE, 0xDC, 0xBA, 0x98, 0x76 };

    std::string block;
    check(buildPinBlock("1234", "5432101234567890", block),
        "returns true for valid input");
    check(block.size() == 8, "writes 8 raw bytes");
    check(std::memcmp(block.data(), expected, 8) == 0,
        "matches ISO 9564 reference vector");

    std::cout << "  pinBlock (hex): " << toHex(block) << "\n";

    std::string dummy;
    check(!buildPinBlock("12", "5432101234567890", dummy),
        "false for short PIN");
    check(!buildPinBlock("1234567890123", "5432101234567890", dummy),
        "false for too-long PIN");
    check(!buildPinBlock("12ab", "5432101234567890", dummy),
        "false for non-digit PIN");
    check(!buildPinBlock("1234", "abcdefghijklmnop", dummy),
        "false for non-digit PAN");
    check(!buildPinBlock("1234", "123456789012", dummy),
        "false for short PAN");
    check(!buildPinBlock("", "5432101234567890", dummy),
        "false for empty PIN");
}

// ---------------------------------------------------------------- CryptoCore

static void testCryptoCore()
{
    section("CryptoCore primitives");

    std::string key = "0123456789ABCDEF";

    // AES
    std::string data = "0123456789ABCDEF"; // 16 bytes
    auto ct = CryptoCore::aesCbcEncrypt(key, data);
    check(ct.has_value(), "aesCbcEncrypt returns value");
    if (ct) {
        check(ct->size() == 32, "AES result = IV(16) + one block");
        auto pt = CryptoCore::aesCbcDecrypt(key, *ct);
        check(pt.has_value() && *pt == data, "AES roundtrip");
    }

    // HMAC
    auto mac = CryptoCore::hmacSha256(key, "hello");
    check(mac.has_value() && mac->size() == 32, "HMAC-SHA256 yields 32 bytes");
    if (mac) {
        check(CryptoCore::hmacVerify(key, "hello", *mac), "HMAC verify ok");
        check(!CryptoCore::hmacVerify(key, "world", *mac),
            "HMAC verify fails on altered data");
    }

    // SHA-256 test vector (RFC): SHA256("abc")
    std::string h = CryptoCore::sha256("abc");
    check(h.size() == 32, "SHA-256 yields 32 bytes");
    check(toHex(h) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 matches test vector");

    // Canonical encoding
    auto c1 = CryptoCore::canonicalEncode("REQ:", { "AB", "C" });
    auto c2 = CryptoCore::canonicalEncode("REQ:", { "A", "BC" });
    check(c1 != c2, "canonical encoding prevents field-boundary collisions");
    check(c1 == "REQ:2:AB1:C", "canonical encoding format");

    // Constant-time compare
    check(CryptoCore::constantTimeEqual("abc", "abc"), "equal strings");
    check(!CryptoCore::constantTimeEqual("abc", "abd"), "unequal strings");
    check(!CryptoCore::constantTimeEqual("abc", "abcd"), "different lengths");
    check(CryptoCore::constantTimeEqual("", ""), "empty strings");

    // Cleanse
    std::string secret = "to be erased";
    CryptoCore::cleanse(secret);
    check(secret.empty(), "cleanse clears the string");

    // Random
    auto r1 = CryptoCore::randomBytes(16);
    auto r2 = CryptoCore::randomBytes(16);
    check(r1.has_value() && r1->size() == 16, "randomBytes(16) yields 16 bytes");
    check(r1 != r2, "randomBytes produces different output");
    check(CryptoCore::randomBytes(0).has_value(), "randomBytes(0) ok");
}

// ---------------------------------------------------------------- AtmHsm lifecycle

static void testAtmHsmLifecycle()
{
    section("AtmHsm lifecycle");

    SignKeyPair signKp = generateSignKeyPair();
    BoxKeyPair  boxKp = generateBoxKeyPair();

    AtmHsm hsm(signKp.pub, boxKp.pub);

    const std::string masterKey = "0123456789ABCDEF";
    const std::string encKey = "FEDCBA9876543210";
    const std::string macKey = "1111222233334444";
    const std::string auditKey = "AAAABBBBCCCCDDDD";

    std::string dummy(8, '\0');

    // Uninitialized
    check(!hsm.isDestroyed(), "not destroyed initially");
    check(!hsm.encryptPinBlock(dummy).has_value(),
        "operations refuse before masterKey installed");

    // Wrong-size master key
    check(!hsm.installMasterKey("short"), "rejects short masterKey");

    // Install master key
    check(hsm.installMasterKey(masterKey), "installMasterKey succeeds");
    check(!hsm.installMasterKey(masterKey), "second installMasterKey fails");

    // Still not operational
    check(!hsm.encryptPinBlock(dummy).has_value(),
        "operations refuse until all working keys present");

    // Load working keys one by one
    auto encBlob = CryptoCore::aesCbcEncrypt(masterKey, encKey);
    auto macBlob = CryptoCore::aesCbcEncrypt(masterKey, macKey);
    auto auditBlob = CryptoCore::aesCbcEncrypt(masterKey, auditKey);
    check(encBlob && macBlob && auditBlob, "working key blobs produced");

    check(hsm.updateWorkingKey(KeyType::Encryption, *encBlob), "install encKey");
    check(!hsm.encryptPinBlock(dummy).has_value(),
        "still not operational (2 of 3 keys)");

    check(hsm.updateWorkingKey(KeyType::Mac, *macBlob), "install macKey");
    check(!hsm.encryptPinBlock(dummy).has_value(),
        "still not operational (1 of 3 keys)");

    check(hsm.updateWorkingKey(KeyType::Audit, *auditBlob), "install auditKey");
    check(hsm.encryptPinBlock(dummy).has_value(),
        "operational after all 3 working keys");

    // Wrong-size blob
    check(!hsm.updateWorkingKey(KeyType::Encryption, "short"),
        "rejects wrong-size key blob");
}

// ---------------------------------------------------------------- MAC

static void testMac(AtmHsm& atm, BankHsm& bank)
{
    section("MAC: AtmHsm <-> BankHsm");

    std::string data = "some canonical data";

    auto mac = atm.macMessage(data);
    check(mac.has_value(), "macMessage returns value");
    if (!mac) return;

    check(mac->size() == 32, "MAC is 32 bytes");
    check(bank.verifyMessage(data, *mac), "server verifies MAC");
    check(!bank.verifyMessage(data + "x", *mac), "altered data rejected");

    auto audit = atm.macAudit("checkpoint content");
    check(audit.has_value(), "macAudit returns value");
    if (audit) {
        check(bank.verifyAudit("checkpoint content", *audit),
            "server verifies audit MAC");
        check(!bank.verifyAudit("other content", *audit),
            "audit MAC bound to content");
    }

    // Cross-check: message MAC must not verify as audit MAC
    check(!bank.verifyAudit(data, *mac),
        "message MAC does not work as audit MAC (key separation)");
}

// ---------------------------------------------------------------- Ed25519 sign/verify

static void testSignAndVerify(AtmHsm& atm, BankHsm& bank)
{
    section("Ed25519: BankHsm::sign -> AtmHsm::verifyServer");

    auto sig = bank.sign(SignDomain::Response, "APPROVED");
    check(sig.has_value(), "sign produces a signature");
    if (!sig) return;

    check(atm.verifyServer(SignDomain::Response, "APPROVED", *sig),
        "ATM verifies RESPONSE signature");
    check(!atm.verifyServer(SignDomain::Command, "APPROVED", *sig),
        "signature does not transfer to another domain");
    check(!atm.verifyServer(SignDomain::Response, "DECLINED", *sig),
        "signature does not verify for different data");

    std::string bad = *sig; bad[0] ^= 0x01;
    check(!atm.verifyServer(SignDomain::Response, "APPROVED", bad),
        "tampered signature rejected");

    auto dispSig = bank.sign(SignDomain::Dispense, "50000");
    check(dispSig && atm.verifyServer(SignDomain::Dispense, "50000", *dispSig),
        "DISPENSE signature verifies");

    auto cmdSig = bank.sign(SignDomain::Command, "RESTORE");
    check(cmdSig && atm.verifyServer(SignDomain::Command, "RESTORE", *cmdSig),
        "COMMAND signature verifies");
}

// ---------------------------------------------------------------- sealed box

static void testSealedBox(AtmHsm& atm, BankHsm& bank)
{
    section("Sealed box: AtmHsm::sealPassword -> BankHsm::openPassword");

    std::string password = "hunter2";

    auto sealed = atm.sealPassword(password);
    check(sealed.has_value(), "sealPassword returns a value");
    if (!sealed) return;

    check(sealed->size() == password.size() + crypto_box_SEALBYTES,
        "sealed box size = plaintext + overhead");
    check(*sealed != password, "sealed box is not plaintext");

    // Correct sealed box -> password recovered in caller's buffer.
    std::string opened;
    check(bank.openPassword(*sealed, opened), "openPassword succeeds");
    check(opened == password, "opened password matches original");
    CryptoCore::cleanse(opened);

    // Tampered sealed box: openPassword fails and wipes the output buffer.
    std::string shouldBeEmpty = "sentinel";
    std::string bad = *sealed; bad[5] ^= 0x01;
    check(!bank.openPassword(bad, shouldBeEmpty), "tampered sealed box rejected");
    check(shouldBeEmpty.empty(), "output wiped on failure");

    // Pre-filled non-empty output must be wiped even on failure, with no
    // residue of the old contents. This is the SSO-safe guarantee.
    std::string preFilled = "AAAAAAAAAAAAAAAA";
    std::string bad2 = *sealed; bad2[7] ^= 0x01;
    check(!bank.openPassword(bad2, preFilled), "tampered sealed box rejected (2)");
    check(preFilled.empty(), "pre-filled out wiped on failure");

    // Too short to be a sealed box.
    std::string tooShort = "abc";
    std::string alsoEmpty = "sentinel";
    check(!bank.openPassword(tooShort, alsoEmpty),
        "too-short sealed box rejected");
    check(alsoEmpty.empty(), "output wiped on too-short input");

    // Empty plaintext is not a valid staff password.
    // (sealPassword succeeds, but openPassword refuses 0-length output.)
    // We do not test this via sealPassword to avoid relying on libsodium's
    // behaviour for empty inputs; the CryptoCore unit test covers the case.
}

// ---------------------------------------------------------------- PinModule

static void testPinModule(AtmHsm& atm, BankHsm& bank)
{
    section("PinModule::processPin");

    PinModule pm(atm);
    Card card("5432101234567890", 12, 2030);
    std::string pan = card.getPan();

    auto pinVerifyValue = bank.computePinVerifyValue(pan, "1234");
    check(pinVerifyValue.has_value(), "computePinVerifyValue returns a value");
    if (!pinVerifyValue) return;

    // Happy path
    auto req = pm.processPin(card, "1234", Action::Withdraw, 50000,
        "S-0001", "ATM-001", 1700000000);
    check(req.has_value(), "processPin returns a request");
    if (!req) return;

    check(req->getAtmId() == "ATM-001", "atmId preserved");
    check(req->getSessionId() == "S-0001", "sessionId preserved");
    check(req->getAction() == Action::Withdraw, "action preserved");
    check(req->getCiphertext().size() == 32, "ciphertext is 32 bytes");
    check(req->getNonce().size() == 16, "nonce is 16 bytes");
    check(req->getTimestamp() == 1700000000, "timestamp preserved");
    check(req->getPan() == pan, "pan preserved");
    check(req->getAmount() == 50000, "amount preserved");
    check(req->getMac().size() == 32, "mac is 32 bytes");

    // Server-side MAC verification
    std::string canonical = CryptoCore::canonicalEncode("REQ:", {
        req->getAtmId(),
        req->getSessionId(),
        std::string(actionToString(req->getAction())),
        req->getCiphertext(),
        req->getNonce(),
        std::to_string(req->getTimestamp()),
        req->getPan(),
        std::to_string(req->getAmount())
        });
    check(bank.verifyMessage(canonical, req->getMac()),
        "server verifies request MAC");

    // Altered action -> MAC breaks
    std::string wrongCanonical = CryptoCore::canonicalEncode("REQ:", {
        req->getAtmId(),
        req->getSessionId(),
        std::string(actionToString(Action::CheckBalance)),
        req->getCiphertext(),
        req->getNonce(),
        std::to_string(req->getTimestamp()),
        req->getPan(),
        std::to_string(req->getAmount())
        });
    check(!bank.verifyMessage(wrongCanonical, req->getMac()),
        "altered action breaks MAC");

    // Server-side PIN verification
    check(bank.verifyPin(req->getCiphertext(), req->getPan(), *pinVerifyValue),
        "server verifies PIN");

    // Failure paths
    check(!pm.processPin(card, "12ab", Action::Withdraw, 50000, "S", "A", 0),
        "non-digit PIN rejected");
    check(!pm.processPin(card, "12", Action::Withdraw, 50000, "S", "A", 0),
        "short PIN rejected");
    check(!pm.processPin(card, "1234", Action::Withdraw, -1, "S", "A", 0),
        "negative amount rejected");

    Card bad("abcdefghijklmnop", 12, 2030);
    check(!pm.processPin(bad, "1234", Action::Withdraw, 50000, "S", "A", 0),
        "non-digit PAN rejected");
}

// ---------------------------------------------------------------- verifyPin

static void testVerifyPin(AtmHsm& atm, BankHsm& bank)
{
    section("BankHsm::verifyPin");

    std::string pan = "5432101234567890";

    auto pinVerifyValue = bank.computePinVerifyValue(pan, "1234");
    check(pinVerifyValue.has_value(), "computePinVerifyValue");
    if (!pinVerifyValue) return;

    std::string pinBlock;
    if (!buildPinBlock("1234", pan, pinBlock)) {
        check(false, "setup: buildPinBlock failed");
        return;
    }
    auto ciphertext = atm.encryptPinBlock(pinBlock);
    if (!ciphertext) { check(false, "setup"); return; }

    check(bank.verifyPin(*ciphertext, pan, *pinVerifyValue),
        "correct PIN verifies");

    // Wrong PIN
    std::string wrongBlock;
    buildPinBlock("9999", pan, wrongBlock);
    auto wrongCt = atm.encryptPinBlock(wrongBlock);
    if (wrongCt) {
        check(!bank.verifyPin(*wrongCt, pan, *pinVerifyValue),
            "wrong PIN rejected");
    }

    // Wrong PAN
    check(!bank.verifyPin(*ciphertext, "1111111111111111", *pinVerifyValue),
        "wrong PAN rejected");

    // Tampered ciphertext
    std::string bad = *ciphertext; bad[20] ^= 0x01;
    check(!bank.verifyPin(bad, pan, *pinVerifyValue),
        "tampered ciphertext rejected");
}

// ---------------------------------------------------------------- working keys

static void testWorkingKeyRotation(BankHsm& bank)
{
    section("BankHsm working key rotation");

    // No pending key yet
    check(!bank.commitWorkingKey(KeyType::Encryption),
        "commit fails without pending key");
    check(!bank.cancelPendingWorkingKey(KeyType::Encryption),
        "cancel fails without pending key");

    // Prepare -> second prepare rejected -> commit works
    auto blob = bank.prepareWorkingKey(KeyType::Encryption);
    check(blob.has_value(), "prepareWorkingKey returns a blob");
    if (!blob) return;

    check(blob->size() == 32, "blob is IV(16) + ciphertext(16)");

    check(!bank.prepareWorkingKey(KeyType::Encryption).has_value(),
        "second prepare for same type is rejected while pending");

    check(bank.commitWorkingKey(KeyType::Encryption),
        "commit succeeds with pending key");
    check(!bank.commitWorkingKey(KeyType::Encryption),
        "second commit fails (pending consumed)");

    check(bank.prepareWorkingKey(KeyType::Encryption).has_value(),
        "prepare allowed again after commit");
    check(bank.cancelPendingWorkingKey(KeyType::Encryption),
        "cleanup: cancel pending Encryption key");

    // Prepare -> cancel -> prepare again allowed
    check(bank.prepareWorkingKey(KeyType::Mac).has_value(),
        "prepare Mac key");
    check(!bank.prepareWorkingKey(KeyType::Mac).has_value(),
        "second prepare Mac rejected");
    check(bank.cancelPendingWorkingKey(KeyType::Mac),
        "cancel pending Mac key");
    check(!bank.cancelPendingWorkingKey(KeyType::Mac),
        "second cancel Mac fails (nothing pending)");
    check(bank.prepareWorkingKey(KeyType::Mac).has_value(),
        "prepare Mac allowed again after cancel");
    check(bank.commitWorkingKey(KeyType::Mac),
        "cleanup: commit Mac key");

    // Cancel must not affect other types.
    check(bank.prepareWorkingKey(KeyType::Audit).has_value(),
        "prepare Audit key");
    check(!bank.cancelPendingWorkingKey(KeyType::Encryption),
        "cancel Encryption while Audit pending does nothing");
    check(bank.cancelPendingWorkingKey(KeyType::Audit),
        "cleanup: cancel Audit key");
}

// ---------------------------------------------------------------- tamper

static void testTamper()
{
    section("AtmHsm::reportTamper");

    SignKeyPair bankSign = generateSignKeyPair();
    BoxKeyPair  bankBox = generateBoxKeyPair();

    const std::string masterKey = "0123456789ABCDEF";
    const std::string encKey = "FEDCBA9876543210";
    const std::string macKey = "1111222233334444";
    const std::string auditKey = "AAAABBBBCCCCDDDD";

    BankHsm bank(masterKey, encKey, macKey, auditKey, "PINPINPINPINPIN1",
        bankSign.pub, bankSign.secret,
        bankBox.pub, bankBox.secret);

    AtmHsm hsm(bankSign.pub, bankBox.pub);
    check(hsm.installMasterKey(masterKey), "setup: installMasterKey");

    auto encBlob = CryptoCore::aesCbcEncrypt(masterKey, encKey);
    auto macBlob = CryptoCore::aesCbcEncrypt(masterKey, macKey);
    auto auditBlob = CryptoCore::aesCbcEncrypt(masterKey, auditKey);
    hsm.updateWorkingKey(KeyType::Encryption, *encBlob);
    hsm.updateWorkingKey(KeyType::Mac, *macBlob);
    hsm.updateWorkingKey(KeyType::Audit, *auditBlob);

    check(!hsm.isDestroyed(), "operational before tamper");
    check(hsm.encryptPinBlock(std::string(8, '\0')).has_value(),
        "encryptPinBlock works before tamper");

    hsm.reportTamper();

    check(hsm.isDestroyed(), "destroyed after tamper");
    check(!hsm.encryptPinBlock(std::string(8, '\0')).has_value(),
        "encryptPinBlock fails after tamper");
    check(!hsm.macMessage("data").has_value(), "macMessage fails after tamper");
    check(!hsm.macAudit("data").has_value(), "macAudit fails after tamper");
    check(!hsm.generateNonce().has_value(), "generateNonce fails after tamper");
    check(!hsm.sealPassword("pwd").has_value(), "sealPassword fails after tamper");

    // verifyServer MUST still work — needed to receive RestoreFromOutOfService
    auto sig = bank.sign(SignDomain::Command, "RESTORE");
    check(sig.has_value(), "bank signs recovery command");
    if (sig) {
        check(hsm.verifyServer(SignDomain::Command, "RESTORE", *sig),
            "Destroyed HSM still verifies recovery command");
    }

    // Idempotent
    hsm.reportTamper();
    check(hsm.isDestroyed(), "reportTamper is idempotent");
}

// ---------------------------------------------------------------- main

int main()
{
    std::cout << "Module 2 test suite\n";
    std::cout << "===================\n";

    // libsodium init — must succeed before any Ed25519 / sealed box call.
    if (!CryptoCore::init()) {
        std::cerr << "FATAL: libsodium initialization failed\n";
        return 1;
    }

    // Shared keys
    const std::string masterKey = "0123456789ABCDEF";
    const std::string encKey = "FEDCBA9876543210";
    const std::string macKey = "1111222233334444";
    const std::string auditKey = "AAAABBBBCCCCDDDD";
    const std::string pinKey = "PINPINPINPINPIN1";

    // Bank keypairs
    SignKeyPair bankSign = generateSignKeyPair();
    BoxKeyPair  bankBox = generateBoxKeyPair();

    // BankHsm (trusted side)
    BankHsm bank(masterKey, encKey, macKey, auditKey, pinKey,
        bankSign.pub, bankSign.secret,
        bankBox.pub, bankBox.secret);

    // AtmHsm (untrusted side) — knows only the bank's public keys
    AtmHsm atm(bankSign.pub, bankBox.pub);

    // Bring the AtmHsm up to Operational
    check(atm.installMasterKey(masterKey), "setup: installMasterKey");
    auto encBlob = CryptoCore::aesCbcEncrypt(masterKey, encKey);
    auto macBlob = CryptoCore::aesCbcEncrypt(masterKey, macKey);
    auto auditBlob = CryptoCore::aesCbcEncrypt(masterKey, auditKey);
    atm.updateWorkingKey(KeyType::Encryption, *encBlob);
    atm.updateWorkingKey(KeyType::Mac, *macBlob);
    atm.updateWorkingKey(KeyType::Audit, *auditBlob);

    // Run the tests
    testCard();
    testPinBlock();
    testCryptoCore();
    testAtmHsmLifecycle();
    testMac(atm, bank);
    testSignAndVerify(atm, bank);
    testSealedBox(atm, bank);
    testPinModule(atm, bank);
    testVerifyPin(atm, bank);
    testTamper();
    testWorkingKeyRotation(bank);   // mutates `bank`, keep last

    std::cout << "\n===================\n";
    std::cout << "PASSED: " << g_passed << "\n";
    std::cout << "FAILED: " << g_failed << "\n";
    return (g_failed == 0) ? 0 : 1;
}
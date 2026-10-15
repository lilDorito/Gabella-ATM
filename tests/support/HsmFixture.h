#pragma once
#include <array>
#include <memory>
#include <sodium.h>
#include <string>

#include "crypto/AtmHsm.h"
#include "crypto/BankHsm.h"
#include "crypto/CryptoCore.h"

struct HsmFixture
{
    static constexpr const char* kMasterKey = "0123456789ABCDEF";
    static constexpr const char* kEncKey = "FEDCBA9876543210";
    static constexpr const char* kMacKey = "1111222233334444";
    static constexpr const char* kAuditKey = "AAAABBBBCCCCDDDD";
    static constexpr const char* kPinKey = "PINPINPINPINPIN1";

    std::array<unsigned char, 32> signPub{};
    std::array<unsigned char, 64> signSecret{};
    std::array<unsigned char, 32> boxPub{};
    std::array<unsigned char, 32> boxSecret{};

    std::unique_ptr<BankHsm> bank;
    std::unique_ptr<AtmHsm> atm;
    bool operational = false;

    explicit HsmFixture(const std::string& auditKey = kAuditKey)
    {
        crypto_sign_keypair(signPub.data(), signSecret.data());
        crypto_box_keypair(boxPub.data(), boxSecret.data());

        bank = std::make_unique<BankHsm>(kMasterKey, kEncKey, kMacKey, auditKey, kPinKey,
            signPub, signSecret, boxPub, boxSecret);
        atm = std::make_unique<AtmHsm>(signPub, boxPub);

        bool ok = atm->installMasterKey(kMasterKey);
        ok = ok && atm->updateWorkingKey(KeyType::Encryption, *CryptoCore::aesCbcEncrypt(kMasterKey, kEncKey));
        ok = ok && atm->updateWorkingKey(KeyType::Mac, *CryptoCore::aesCbcEncrypt(kMasterKey, kMacKey));
        ok = ok && atm->updateWorkingKey(KeyType::Audit, *CryptoCore::aesCbcEncrypt(kMasterKey, auditKey));
        operational = ok && atm->state() == AtmHsmState::Operational;
    }
};

#pragma once
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "crypto/CryptoCore.h"
#include "crypto/HsmTypes.h"
#include "crypto/SignDomain.h"

class BankHsm final
{
private:
    std::string _masterKey;
    std::string _encKey;
    std::string _macKey;
    std::string _auditKey;
    std::string _pinKey;   

    std::array<unsigned char, 32> _signPublic;   
    std::array<unsigned char, 64> _signSecret;   
    std::array<unsigned char, 32> _boxPublic;    
    std::array<unsigned char, 32> _boxSecret;    

    std::map<KeyType, std::string> _pendingKeys;

    void wipeKeys();

    bool extractPin(const std::string& pinBlock,
        const std::string& pan,
        std::string& out) const;

public:
    BankHsm(const std::string& masterKey,
        const std::string& encKey,
        const std::string& macKey,
        const std::string& auditKey,
        const std::string& pinKey,
        std::array<unsigned char, 32> signPublic,
        std::array<unsigned char, 64> signSecret,
        std::array<unsigned char, 32> boxPublic,
        std::array<unsigned char, 32> boxSecret);

    ~BankHsm();

    BankHsm(const BankHsm&) = delete;
    BankHsm& operator=(const BankHsm&) = delete;
    BankHsm(BankHsm&&) = delete;
    BankHsm& operator=(BankHsm&&) = delete;

    [[nodiscard]] bool verifyMessage(const std::string& data,
        const std::string& mac) const;

    [[nodiscard]] bool verifyAudit(const std::string& data,
        const std::string& mac) const;

    [[nodiscard]] std::optional<std::string> macAudit(const std::string& data) const;

    [[nodiscard]] std::optional<std::string> sign(SignDomain domain,
        const std::string& data) const;

    [[nodiscard]] bool verifyPin(const std::string& encryptedBlock,
        const std::string& pan,
        const std::string& pinVerifyValue) const;

    [[nodiscard]] std::optional<std::string> computePinVerifyValue(const std::string& pan,
        const std::string& pin) const;

    [[nodiscard]] bool openPassword(const std::string& sealed, std::string& out) const;

    [[nodiscard]] std::optional<std::string> prepareWorkingKey(KeyType type);

    [[nodiscard]] bool commitWorkingKey(KeyType type);

    [[nodiscard]] bool cancelPendingWorkingKey(KeyType type);

    [[nodiscard]] std::array<unsigned char, 32> signPublicKey() const;
    [[nodiscard]] std::array<unsigned char, 32> boxPublicKey() const;
};
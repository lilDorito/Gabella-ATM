#pragma once
#include "crypto/CryptoCore.h"
#include "crypto/PinBlock.h"
#include "crypto/SignDomain.h"
#include "crypto/HsmTypes.h"
#include <array>
#include <optional>
#include <string>

enum class AtmHsmState { 
    Uninitialized,
    MasterInstalled, 
    Operational,     
    Destroyed       
};

class AtmHsm final
{
private:
    std::string _masterKey;
    std::string _encKey;
    std::string _macKey;
    std::string _auditKey;

    std::array<unsigned char, 32> _serverSignPublic;
    std::array<unsigned char, 32> _serverBoxPublic;

    AtmHsmState _state;

    void wipeKeys();

public:
    AtmHsm(std::array<unsigned char, 32> serverSignPublic,
        std::array<unsigned char, 32> serverBoxPublic)
        : _serverSignPublic(serverSignPublic),
        _serverBoxPublic(serverBoxPublic),
        _state(AtmHsmState::Uninitialized) {}

    ~AtmHsm();

    AtmHsm(const AtmHsm&) = delete;
    AtmHsm& operator=(const AtmHsm&) = delete;
    AtmHsm(AtmHsm&&) = delete;
    AtmHsm& operator=(AtmHsm&&) = delete;

    [[nodiscard]] bool installMasterKey(const std::string& masterKey);

    std::optional<std::string> encryptPinBlock(const std::string& pinBlock) const;

    std::optional<std::string> macMessage(const std::string& data) const;

    std::optional<std::string> macAudit(const std::string& data) const;

    bool updateWorkingKey(KeyType type, const std::string& encryptedNewKey);

    [[nodiscard]] bool verifyServer(SignDomain domain,
        const std::string& data,
        const std::string& signature) const;

    [[nodiscard]] std::optional<std::string> sealPassword(const std::string& password) const;

    std::optional<std::string> generateNonce() const;

    void reportTamper();

    AtmHsmState state() const;

    bool isDestroyed() const;
};
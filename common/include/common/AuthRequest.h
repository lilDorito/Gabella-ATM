#pragma once
#include <string>
#include <cstdint>
#include "common/Action.h"

class AuthRequest
{
private:
	std::string  _atmId;
	std::string  _sessionId;
	Action       _action;
	std::string  _ciphertext;
	std::string  _nonce;
	std::int64_t _timestamp;
	std::string  _pan;
	std::int64_t _amount;
	std::string  _mac;

public:
    AuthRequest(const std::string& atmId,
        const std::string& sessionId,
        Action action,
        const std::string& ciphertext,
        const std::string& nonce,
        std::int64_t timestamp,
        const std::string& pan,
        std::int64_t amount,
        const std::string& mac);

    const std::string& getAtmId() const;
    const std::string& getSessionId() const;
    Action getAction() const;
    const std::string& getCiphertext() const;
    const std::string& getNonce() const;
    std::int64_t getTimestamp() const;
    const std::string& getPan() const;
    std::int64_t getAmount() const;
    const std::string& getMac() const;
};
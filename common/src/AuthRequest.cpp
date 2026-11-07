#include "common/AuthRequest.h"

#include "common/Canonical.h"

AuthRequest::AuthRequest(const std::string& atmId,
    const std::string& sessionId,
    Action action,
    const std::string& ciphertext,
    const std::string& nonce,
    std::int64_t timestamp,
    const std::string& pan,
    std::int64_t amount,
    const std::string& mac)
    : _atmId(atmId),
      _sessionId(sessionId),
      _action(action),
      _ciphertext(ciphertext),
      _nonce(nonce),
      _timestamp(timestamp),
      _pan(pan),
      _amount(amount),
      _mac(mac)
{
}

const std::string& AuthRequest::getAtmId() const { return _atmId; }
const std::string& AuthRequest::getSessionId() const { return _sessionId; }
Action AuthRequest::getAction() const { return _action; }
const std::string& AuthRequest::getCiphertext() const { return _ciphertext; }
const std::string& AuthRequest::getNonce() const { return _nonce; }
std::int64_t AuthRequest::getTimestamp() const { return _timestamp; }
const std::string& AuthRequest::getPan() const { return _pan; }
std::int64_t AuthRequest::getAmount() const { return _amount; }
const std::string& AuthRequest::getMac() const { return _mac; }

std::string AuthRequest::macPayload() const
{
    return canonicalEncode("REQ:", { _atmId, _sessionId, std::string(actionToString(_action)), _ciphertext, _nonce, std::to_string(_timestamp), _pan, std::to_string(_amount) });
}

std::string AuthRequest::pinBinding() const { return pinBinding(_atmId, _sessionId, _action, _nonce, _timestamp, _pan, _amount); }

std::string
AuthRequest::pinBinding(const std::string& atmId, const std::string& sessionId, Action action, const std::string& nonce, std::int64_t timestamp, const std::string& pan, std::int64_t amount)
{
    return canonicalEncode("PINCTX:", { atmId, sessionId, std::string(actionToString(action)), nonce, std::to_string(timestamp), pan, std::to_string(amount) });
}

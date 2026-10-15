#include "crypto/AtmHsm.h"

void AtmHsm::wipeKeys()
{
	CryptoCore::cleanse(_masterKey);
	CryptoCore::cleanse(_encKey);
	CryptoCore::cleanse(_macKey);
	CryptoCore::cleanse(_auditKey);
}

AtmHsm::~AtmHsm()
{
	wipeKeys();
}

bool AtmHsm::installMasterKey(const std::string& masterKey)
{
	if (_state != AtmHsmState::Uninitialized) return false;

	if (masterKey.size() != 16) return false;

	_masterKey = masterKey;
	_state = AtmHsmState::MasterInstalled;
	return true;
}

std::optional<std::string> AtmHsm::encryptPinBlock(const std::string& pinBlock) const
{
	if (_state != AtmHsmState::Operational) return std::nullopt;
	if (_encKey.size() != 16) return std::nullopt;

	return CryptoCore::encryptPinBlock(_encKey, pinBlock);
}

std::optional<std::string> AtmHsm::macMessage(const std::string& data) const
{
	if (_state != AtmHsmState::Operational) return std::nullopt;
	if (_macKey.size() != 16) return std::nullopt;

	return CryptoCore::hmacSha256(_macKey, data);
}

std::optional<std::string> AtmHsm::macAudit(const std::string& data) const
{
	if (_state != AtmHsmState::Operational) return std::nullopt;
	if (_auditKey.size() != 16) return std::nullopt;

	return CryptoCore::hmacSha256(_auditKey, "AUDIT:" + data);
}

bool AtmHsm::updateWorkingKey(KeyType type, const std::string& encryptedNewKey)
{
	if (_state != AtmHsmState::MasterInstalled && _state != AtmHsmState::Operational) return false;
	if (_masterKey.size() != 16) return false;

	auto plaintext = CryptoCore::aesCbcDecrypt(_masterKey, encryptedNewKey);
	if (!plaintext) return false;

	switch (type) {
	case KeyType::Encryption: _encKey.assign(plaintext->data(), plaintext->size()); break;
	case KeyType::Mac:        _macKey.assign(plaintext->data(), plaintext->size()); break;
	case KeyType::Audit:      _auditKey.assign(plaintext->data(), plaintext->size()); break;
	}

	CryptoCore::cleanse(*plaintext);

	if (_encKey.size() == 16 && _macKey.size() == 16 && _auditKey.size() == 16)
	{
		_state = AtmHsmState::Operational;
	}

	return true;
}

bool AtmHsm::verifyServer(SignDomain domain,
	const std::string& data,
	const std::string& signature) const
{
	const std::string tagged = std::string(tagOf(domain)) + data;
	return CryptoCore::ed25519Verify(_serverSignPublic, tagged, signature);
}

std::optional<std::string> AtmHsm::sealPassword(const std::string& password) const
{
	if (_state != AtmHsmState::Operational) return std::nullopt;
	return CryptoCore::sealedBoxSeal(_serverBoxPublic, password);
}

std::optional<std::string> AtmHsm::generateNonce() const
{
	if (_state != AtmHsmState::Operational) return std::nullopt;

	return CryptoCore::randomBytes(16);
}

AtmHsmState AtmHsm::state() const { return _state; }

void AtmHsm::reportTamper()
{
	if (_state == AtmHsmState::Destroyed) return;

	wipeKeys();
	_state = AtmHsmState::Destroyed;
}

bool AtmHsm::isDestroyed() const
{
	return _state == AtmHsmState::Destroyed;
}
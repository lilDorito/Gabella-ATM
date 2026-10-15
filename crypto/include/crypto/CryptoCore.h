#pragma once
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <optional>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sodium.h>
#include <array>
#include "crypto/PinBlock.h"  

namespace CryptoCore {

	std::optional<std::string> hmacSha256(const std::string& key,
		const std::string& data);

	bool hmacVerify(const std::string& key,
		const std::string& data,
		const std::string& mac);

	std::optional<std::string> aesCbcEncrypt(const std::string& key,
		const std::string& data);

	std::optional<std::string> aesCbcDecrypt(const std::string& key,
		const std::string& data);

	std::optional<std::string> encryptPinBlock(const std::string& key,
		const std::string& pinBlock);

	std::optional<std::string> randomBytes(std::size_t n);

	std::string sha256(const std::string& data);

	void cleanse(std::string& s);

	void cleanse(void* buf, std::size_t n);

	bool constantTimeEqual(const std::string& a, const std::string& b);

	std::string canonicalEncode(const std::string& tag,
		const std::vector<std::string>& fields);

	bool init();

	std::optional<std::string> ed25519Sign(
		const std::array<unsigned char, crypto_sign_SECRETKEYBYTES>& secretKey,
		const std::string& message);

	bool ed25519Verify(
		const std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>& publicKey,
		const std::string& message,
		const std::string& signature);

	bool sealedBoxOpen(
		const std::array<unsigned char, crypto_box_PUBLICKEYBYTES>& recipientPublicKey,
		const std::array<unsigned char, crypto_box_SECRETKEYBYTES>& recipientSecretKey,
		const std::string& ciphertext,
		std::string& out);

	std::optional<std::string> sealedBoxSeal(
		const std::array<unsigned char, crypto_box_PUBLICKEYBYTES>& recipientPublicKey,
		const std::string& plaintext);

	class StringWiper
	{
		std::string& _s;
	public:
		explicit StringWiper(std::string& s) : _s(s) {}
		~StringWiper() { cleanse(_s); }

		StringWiper(const StringWiper&) = delete;
		StringWiper& operator=(const StringWiper&) = delete;
		StringWiper(StringWiper&&) = delete;
		StringWiper& operator=(StringWiper&&) = delete;
	};

	class BufWiper
	{
		void* _p;
		std::size_t _n;
	public:
		BufWiper(void* p, std::size_t n) : _p(p), _n(n) {}
		~BufWiper() { cleanse(_p, _n); }

		BufWiper(const BufWiper&) = delete;
		BufWiper& operator=(const BufWiper&) = delete;
		BufWiper(BufWiper&&) = delete;
		BufWiper& operator=(BufWiper&&) = delete;
	};
} 
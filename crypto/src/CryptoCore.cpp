#include "crypto/CryptoCore.h"

namespace {

	constexpr std::size_t AES_BLOCK_SIZE = 16;
}

std::optional<std::string> CryptoCore::hmacSha256(const std::string& key,
	const std::string& data)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  digest_len = 0;

	if (HMAC(EVP_sha256(),
		key.data(),
		static_cast<int>(key.size()),
		reinterpret_cast<const unsigned char*>(data.data()),
		data.size(),
		digest,
		&digest_len) == nullptr)
	{
		return std::nullopt;
	}

	return std::string(reinterpret_cast<char*>(digest), digest_len);
}

bool CryptoCore::hmacVerify(const std::string& key,
	const std::string& data,
	const std::string& mac)
{
	auto computed = hmacSha256(key, data);

	if (!computed) return false;
	if (computed->size() != mac.size()) return false;

	return CRYPTO_memcmp(computed->data(), mac.data(), computed->size()) == 0;
}

std::optional<std::string> CryptoCore::aesCbcEncrypt(const std::string& key,
	const std::string& data)
{
	if (key.size() != 16) return std::nullopt;
	if (data.empty() || data.size() % AES_BLOCK_SIZE != 0) return std::nullopt;

	unsigned char iv[AES_BLOCK_SIZE];
	if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) return std::nullopt;

	unsigned char ivCopy[AES_BLOCK_SIZE];
	std::memcpy(ivCopy, iv, AES_BLOCK_SIZE);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return std::nullopt;

	std::string ciphertext(data.size(), '\0');
	int out_len = 0;
	int final_len = 0;

	bool ok =
		EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
			reinterpret_cast<const unsigned char*>(key.data()),
			iv) == 1 &&
		EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
		EVP_EncryptUpdate(ctx,
			reinterpret_cast<unsigned char*>(&ciphertext[0]), &out_len,
			reinterpret_cast<const unsigned char*>(data.data()),
			static_cast<int>(data.size())) == 1 &&
		EVP_EncryptFinal_ex(ctx,
			reinterpret_cast<unsigned char*>(&ciphertext[0]) + out_len,
			&final_len) == 1;

	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(iv, AES_BLOCK_SIZE);

	if (!ok) return std::nullopt;

	ciphertext.resize(static_cast<std::size_t>(out_len + final_len));

	std::string result;
	result.reserve(AES_BLOCK_SIZE + ciphertext.size());
	result.append(reinterpret_cast<const char*>(ivCopy), AES_BLOCK_SIZE);
	result.append(ciphertext);
	return result;
}

std::optional<std::string> CryptoCore::aesCbcDecrypt(const std::string& key,
	const std::string& data)
{
	if (key.size() != 16) return std::nullopt;
	if (data.size() != 2 * AES_BLOCK_SIZE) return std::nullopt;

	unsigned char iv[AES_BLOCK_SIZE];
	std::memcpy(iv, data.data(), AES_BLOCK_SIZE);

	const unsigned char* ciphertext =
		reinterpret_cast<const unsigned char*>(data.data() + AES_BLOCK_SIZE);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return std::nullopt;

	unsigned char plaintext[AES_BLOCK_SIZE];
	int out_len = 0;
	int final_len = 0;

	bool ok =
		EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
			reinterpret_cast<const unsigned char*>(key.data()),
			iv) == 1 &&
		EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
		EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, AES_BLOCK_SIZE) == 1 &&
		EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) == 1;

	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(iv, AES_BLOCK_SIZE);

	if (!ok)
	{
		OPENSSL_cleanse(plaintext, AES_BLOCK_SIZE);
		return std::nullopt;
	}

	std::string result(reinterpret_cast<char*>(plaintext), AES_BLOCK_SIZE);
	OPENSSL_cleanse(plaintext, AES_BLOCK_SIZE);

	return result;
}

std::optional<std::string> CryptoCore::encryptPinBlock(const std::string& key,
	const std::string& pinBlock)
{
	if (key.size() != 16) return std::nullopt;
	if (pinBlock.size() != 8) return std::nullopt;

	unsigned char iv[AES_BLOCK_SIZE];
	if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) return std::nullopt;

	unsigned char ivCopy[AES_BLOCK_SIZE];
	std::memcpy(ivCopy, iv, AES_BLOCK_SIZE);

	unsigned char padded[AES_BLOCK_SIZE];
	std::memcpy(padded, pinBlock.data(), 8);
	std::memset(padded + 8, 0x08, 8);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		OPENSSL_cleanse(padded, AES_BLOCK_SIZE);
		OPENSSL_cleanse(iv, AES_BLOCK_SIZE);
		return std::nullopt;
	}

	unsigned char ciphertext[AES_BLOCK_SIZE];
	int out_len = 0;
	int final_len = 0;

	bool ok =
		EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
			reinterpret_cast<const unsigned char*>(key.data()),
			iv) == 1 &&
		EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
		EVP_EncryptUpdate(ctx, ciphertext, &out_len, padded, AES_BLOCK_SIZE) == 1 &&
		EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) == 1;

	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(padded, AES_BLOCK_SIZE);
	OPENSSL_cleanse(iv, AES_BLOCK_SIZE);

	if (!ok) return std::nullopt;

	std::string result;
	result.append(reinterpret_cast<const char*>(ivCopy), AES_BLOCK_SIZE);
	result.append(reinterpret_cast<const char*>(ciphertext), AES_BLOCK_SIZE);
	return result;
}

std::optional<std::string> CryptoCore::randomBytes(std::size_t n)
{
	if (n == 0) return std::string();

	std::string buf(n, '\0');
	if (RAND_bytes(reinterpret_cast<unsigned char*>(&buf[0]),
		static_cast<int>(n)) != 1)
	{
		return std::nullopt;
	}
	return buf;
}

std::string CryptoCore::sha256(const std::string& data)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!ctx) return "";

	bool ok =
		EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
		EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
		EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1;

	EVP_MD_CTX_free(ctx);
	if (!ok) return "";

	return std::string(reinterpret_cast<char*>(digest), digest_len);
}

void CryptoCore::cleanse(std::string& s)
{
	if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());

	s.clear();
}

void CryptoCore::cleanse(void* buf, std::size_t n)
{
	if (buf && n > 0) OPENSSL_cleanse(buf, n);
}

bool CryptoCore::constantTimeEqual(const std::string& a, const std::string& b)
{
	if (a.size() != b.size()) return false;
	if (a.empty()) return true;

	return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string CryptoCore::canonicalEncode(const std::string& tag,
	const std::vector<std::string>& fields)
{
	std::string out = tag;
	for (const auto& f : fields)
	{
		out += std::to_string(f.size()) + ":" + f;
	}
	return out;
}

 bool CryptoCore::init()
{
	return sodium_init() >= 0;
}

std::optional<std::string> CryptoCore::ed25519Sign(
	const std::array<unsigned char, crypto_sign_SECRETKEYBYTES>& secretKey,
	const std::string& message)
{
	std::string signature(crypto_sign_BYTES, '\0');
	unsigned long long sigLen = 0;

	if (crypto_sign_detached(
		reinterpret_cast<unsigned char*>(&signature[0]),
		&sigLen,
		reinterpret_cast<const unsigned char*>(message.data()),
		message.size(),
		secretKey.data()) != 0)
	{
		return std::nullopt;
	}

	return signature;
}

bool CryptoCore::ed25519Verify(
	const std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>& publicKey,
	const std::string& message,
	const std::string& signature)
{
	if (signature.size() != crypto_sign_BYTES) return false;

	return crypto_sign_verify_detached(
		reinterpret_cast<const unsigned char*>(signature.data()),
		reinterpret_cast<const unsigned char*>(message.data()),
		message.size(),
		publicKey.data()) == 0;
}

bool CryptoCore::sealedBoxOpen(
	const std::array<unsigned char, crypto_box_PUBLICKEYBYTES>& recipientPublicKey,
	const std::array<unsigned char, crypto_box_SECRETKEYBYTES>& recipientSecretKey,
	const std::string& ciphertext,
	std::string& out)
{
	cleanse(out);

	if (ciphertext.size() < crypto_box_SEALBYTES)
	{
		cleanse(out);
		return false;
	}

	const std::size_t ptLen = ciphertext.size() - crypto_box_SEALBYTES;
	if (ptLen == 0)
	{
		cleanse(out);
		return false;
	}

	out.resize(ptLen);

	if (crypto_box_seal_open(
		reinterpret_cast<unsigned char*>(&out[0]),
		reinterpret_cast<const unsigned char*>(ciphertext.data()),
		ciphertext.size(),
		recipientPublicKey.data(),
		recipientSecretKey.data()) != 0)
	{
		cleanse(out);
		return false;
	}

	return true;
}

std::optional<std::string> CryptoCore::sealedBoxSeal(
	const std::array<unsigned char, crypto_box_PUBLICKEYBYTES>& recipientPublicKey,
	const std::string& plaintext)
{
	std::string ciphertext(plaintext.size() + crypto_box_SEALBYTES, '\0');

	if (crypto_box_seal(
		reinterpret_cast<unsigned char*>(&ciphertext[0]),
		reinterpret_cast<const unsigned char*>(plaintext.data()),
		plaintext.size(),
		recipientPublicKey.data()) != 0)
	{
		return std::nullopt;
	}

	return ciphertext;
}
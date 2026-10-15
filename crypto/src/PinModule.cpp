#include "crypto/PinModule.h"
#include "crypto/CryptoCore.h"
#include "crypto/PinBlock.h"

std::optional<AuthRequest> PinModule::processPin(
    const Card& card,
    const std::string& pin,
    Action action,
    std::int64_t amount,
    const std::string& sessionId,
    const std::string& atmId,
    std::int64_t timestamp) const
{
    if (amount < 0) return std::nullopt;

    std::string pan = card.getPan();

    std::string pinBlock;
    CryptoCore::StringWiper pinBlockWiper{ pinBlock };
    if (!buildPinBlock(pin, pan, pinBlock)) return std::nullopt;

    auto ciphertext = _hsm.encryptPinBlock(pinBlock);
    if (!ciphertext) return std::nullopt;

    auto nonce = _hsm.generateNonce();
    if (!nonce) return std::nullopt;

    std::string canonical = CryptoCore::canonicalEncode("REQ:", {
        atmId,
        sessionId,
        std::string(actionToString(action)),
        *ciphertext,
        *nonce,
        std::to_string(timestamp),
        pan,
        std::to_string(amount)
        });

    auto mac = _hsm.macMessage(canonical);
    if (!mac) return std::nullopt;

    return AuthRequest(atmId, sessionId, action,
        *ciphertext, *nonce, timestamp,
        pan, amount, *mac);
}
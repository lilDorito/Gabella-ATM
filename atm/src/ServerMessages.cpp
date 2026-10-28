#include "atm/ServerMessages.h"

#include "crypto/CryptoCore.h"

std::string DispenseCommand::signedPayload() const
{
    return CryptoCore::canonicalEncode("", {
        atmId,
        sessionId,
        std::to_string(amountKop),
        std::to_string(sequence)
        });
}

std::string SignedCommand::signedPayload() const
{
    return CryptoCore::canonicalEncode("", {
        atmId,
        std::to_string(commandSeq),
        std::string(actionToString(action)),
        params
        });
}

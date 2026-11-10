#include "server/repo/CardRepository.h"

#include "common/Hex.h"
#include "server/db/DbError.h"
#include "server/db/Statement.h"

void CardRepository::insert(const CardRecord& card)
{
    Statement s(_db, "INSERT INTO cards (pan, account_id, exp_month, exp_year, pin_verify_value, failed_pin_attempts, status) VALUES (?, ?, ?, ?, ?, ?, ?)");
    s.bind(1, card.pan)
        .bind(2, card.accountId)
        .bind(3, static_cast<std::int64_t>(card.expMonth))
        .bind(4, static_cast<std::int64_t>(card.expYear))
        .bind(5, toHex(card.pinVerifyValue))
        .bind(6, static_cast<std::int64_t>(card.failedPinAttempts))
        .bind(7, std::string(card.blocked ? "BLOCKED" : "ACTIVE"))
        .run();
}

std::optional<CardRecord> CardRepository::find(const std::string& pan) const
{
    Statement s(_db, "SELECT pan, account_id, exp_month, exp_year, pin_verify_value, failed_pin_attempts, status FROM cards WHERE pan = ?");
    s.bind(1, pan);
    if (!s.step()) return std::nullopt;

    CardRecord card;
    card.pan = s.columnText(0);
    card.accountId = s.columnText(1);
    card.expMonth = static_cast<int>(s.columnInt64(2));
    card.expYear = static_cast<int>(s.columnInt64(3));
    auto pinVerifyValue = fromHex(s.columnText(4));
    if (!pinVerifyValue) throw DbError(0, "stored PIN verify value is not hex");
    card.pinVerifyValue = std::move(*pinVerifyValue);
    card.failedPinAttempts = static_cast<std::uint32_t>(s.columnInt64(5));
    card.blocked = s.columnText(6) == "BLOCKED";
    return card;
}

PinFailure CardRepository::recordFailedPin(const std::string& pan, std::uint32_t maxWrongPins)
{
    {
        Statement update(_db,
            "UPDATE cards SET failed_pin_attempts = failed_pin_attempts + 1, "
            "status = CASE WHEN failed_pin_attempts + 1 >= ? THEN 'BLOCKED' ELSE status END WHERE pan = ?");
        update.bind(1, static_cast<std::int64_t>(maxWrongPins)).bind(2, pan).run();
    }
    if (_db.changes() != 1) throw DbError(0, "card to count a failed PIN for does not exist");

    const auto card = find(pan);
    if (!card) throw DbError(0, "card vanished while counting a failed PIN");
    return PinFailure{ card->failedPinAttempts, card->blocked };
}

void CardRepository::resetFailedPins(const std::string& pan)
{
    Statement s(_db, "UPDATE cards SET failed_pin_attempts = 0 WHERE pan = ?");
    s.bind(1, pan).run();
}

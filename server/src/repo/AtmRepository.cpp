#include "server/repo/AtmRepository.h"

#include "server/db/DbError.h"
#include "server/db/Statement.h"

const char* atmStatusToString(AtmStatus status)
{
    switch (status)
    {
    case AtmStatus::Active: return "ACTIVE";
    case AtmStatus::OutOfService: return "OUT_OF_SERVICE";
    }
    return "";
}

void AtmRepository::insert(const std::string& atmId)
{
    if (atmId.empty() || atmId == "SERVER") throw DbError(0, "reserved or empty ATM id");
    Statement s(_db, "INSERT INTO atms (atm_id, status) VALUES (?, 'ACTIVE')");
    s.bind(1, atmId).run();
}

std::optional<AtmRecord> AtmRepository::find(const std::string& atmId) const
{
    Statement s(_db, "SELECT atm_id, status, last_dispense_seq, last_command_seq, log_review_required FROM atms WHERE atm_id = ?");
    s.bind(1, atmId);
    if (!s.step()) return std::nullopt;

    AtmRecord r;
    r.atmId = s.columnText(0);
    r.status = s.columnText(1) == "ACTIVE" ? AtmStatus::Active : AtmStatus::OutOfService;
    r.lastDispenseSeq = static_cast<std::uint64_t>(s.columnInt64(2));
    r.lastCommandSeq = static_cast<std::uint64_t>(s.columnInt64(3));
    r.logReviewRequired = s.columnInt64(4) != 0;
    return r;
}

std::vector<AtmRecord> AtmRepository::all() const
{
    Statement s(_db, "SELECT atm_id, status, last_dispense_seq, last_command_seq, log_review_required FROM atms ORDER BY atm_id");
    std::vector<AtmRecord> out;
    while (s.step())
    {
        AtmRecord r;
        r.atmId = s.columnText(0);
        r.status = s.columnText(1) == "ACTIVE" ? AtmStatus::Active : AtmStatus::OutOfService;
        r.lastDispenseSeq = static_cast<std::uint64_t>(s.columnInt64(2));
        r.lastCommandSeq = static_cast<std::uint64_t>(s.columnInt64(3));
        r.logReviewRequired = s.columnInt64(4) != 0;
        out.push_back(r);
    }
    return out;
}

bool AtmRepository::setStatus(const std::string& atmId, AtmStatus status)
{
    Statement s(_db, "UPDATE atms SET status = ? WHERE atm_id = ?");
    s.bind(1, std::string(atmStatusToString(status))).bind(2, atmId).run();
    return _db.changes() == 1;
}

bool AtmRepository::flagLogReview(const std::string& atmId)
{
    Statement s(_db, "UPDATE atms SET log_review_required = 1 WHERE atm_id = ?");
    s.bind(1, atmId).run();
    return _db.changes() == 1;
}

#include "server/repo/CassetteRepository.h"

#include "server/db/DbError.h"
#include "server/db/Statement.h"

bool CassetteRepository::isValidDenomination(int denomination) { return denomination == 100 || denomination == 200 || denomination == 500 || denomination == 1000; }

std::map<int, int> CassetteRepository::expected(const std::string& atmId) const
{
    Statement s(_db, "SELECT denomination, expected_count FROM atm_cassettes WHERE atm_id = ?");
    s.bind(1, atmId);

    std::map<int, int> counts;
    while (s.step()) counts[static_cast<int>(s.columnInt64(0))] = static_cast<int>(s.columnInt64(1));
    return counts;
}

void CassetteRepository::replace(const std::string& atmId, const std::map<int, int>& counts)
{
    for (const auto& [denomination, count] : counts)
    {
        if (!isValidDenomination(denomination) || count < 0) throw DbError(0, "invalid cassette definition");

        Statement s(_db, "INSERT INTO atm_cassettes (atm_id, denomination, expected_count) VALUES (?, ?, ?) ON CONFLICT (atm_id, denomination) DO UPDATE SET expected_count = excluded.expected_count");
        s.bind(1, atmId).bind(2, static_cast<std::int64_t>(denomination)).bind(3, static_cast<std::int64_t>(count)).run();
    }
}

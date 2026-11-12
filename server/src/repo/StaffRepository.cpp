#include "server/repo/StaffRepository.h"

#include "server/db/DbError.h"
#include "server/db/Statement.h"

const char* StaffRepository::roleToColumn(Role role)
{
    switch (role)
    {
    case Role::ServiceEngineer: return "ServiceEngineer";
    case Role::CashCollector: return "CashCollector";
    case Role::Auditor: return "Auditor";
    case Role::Admin: return "Admin";
    case Role::Client:
    case Role::System: break;
    }
    return "";
}

std::optional<Role> StaffRepository::roleFromColumn(const std::string& text)
{
    if (text == "ServiceEngineer") return Role::ServiceEngineer;
    if (text == "CashCollector") return Role::CashCollector;
    if (text == "Auditor") return Role::Auditor;
    if (text == "Admin") return Role::Admin;
    return std::nullopt;
}

void StaffRepository::insert(const StaffRecord& staff)
{
    const std::string role = roleToColumn(staff.role);
    if (role.empty()) throw DbError(0, "staff role is not allowed");

    Statement s(_db, "INSERT INTO staff (staff_id, role, password_hash, failed_logins, locked_until, status) VALUES (?, ?, ?, ?, ?, ?)");
    s.bind(1, staff.staffId)
        .bind(2, role)
        .bind(3, staff.passwordHash)
        .bind(4, static_cast<std::int64_t>(staff.failedLogins))
        .bind(5, staff.lockedUntil)
        .bind(6, std::string(staff.active ? "ACTIVE" : "DISABLED"))
        .run();
}

std::optional<StaffRecord> StaffRepository::find(const std::string& staffId) const
{
    Statement s(_db, "SELECT staff_id, role, password_hash, failed_logins, locked_until, status FROM staff WHERE staff_id = ?");
    s.bind(1, staffId);
    if (!s.step()) return std::nullopt;

    const auto role = roleFromColumn(s.columnText(1));
    if (!role) throw DbError(0, "stored staff role is not valid");

    StaffRecord r;
    r.staffId = s.columnText(0);
    r.role = *role;
    r.passwordHash = s.columnText(2);
    r.failedLogins = static_cast<std::uint32_t>(s.columnInt64(3));
    r.lockedUntil = s.columnInt64(4);
    r.active = s.columnText(5) == "ACTIVE";
    return r;
}

LoginFailure StaffRepository::recordFailure(const std::string& staffId, std::int64_t now, std::uint32_t maxFailures, std::int64_t lockoutSeconds)
{
    {
        Statement update(_db,
            "UPDATE staff SET "
            "failed_logins = CASE WHEN locked_until <> 0 AND locked_until <= ?1 THEN 1 ELSE failed_logins + 1 END, "
            "locked_until = CASE "
            "WHEN locked_until > ?1 THEN locked_until "
            "WHEN (CASE WHEN locked_until <> 0 THEN 1 ELSE failed_logins + 1 END) >= ?2 THEN ?1 + ?3 "
            "ELSE 0 END "
            "WHERE staff_id = ?4");
        update.bind(1, now).bind(2, static_cast<std::int64_t>(maxFailures)).bind(3, lockoutSeconds).bind(4, staffId).run();
    }
    if (_db.changes() != 1) throw DbError(0, "staff to count a failed login for does not exist");

    const auto staff = find(staffId);
    if (!staff) throw DbError(0, "staff vanished while counting a failed login");
    LoginFailure f;
    f.attempts = staff->failedLogins;
    f.locked = staff->lockedUntil > now;
    f.lockedUntil = staff->lockedUntil;
    return f;
}

void StaffRepository::resetFailures(const std::string& staffId)
{
    Statement s(_db, "UPDATE staff SET failed_logins = 0, locked_until = 0 WHERE staff_id = ?");
    s.bind(1, staffId).run();
}

std::uint32_t StaffRepository::countActiveAdmins() const
{
    Statement s(_db, "SELECT count(*) FROM staff WHERE role = 'Admin' AND status = 'ACTIVE'");
    return s.step() ? static_cast<std::uint32_t>(s.columnInt64(0)) : 0;
}

#include "server/db/Statement.h"

#include <sqlite3.h>

#include "server/db/DbError.h"

Statement::Statement(Database& db, const char* sql) : _db(db)
{
    const int rc = sqlite3_prepare_v2(_db.handle(), sql, -1, &_stmt, nullptr);
    if (rc != SQLITE_OK) throw DbError(rc, sqlite3_errmsg(_db.handle()));
}

Statement::~Statement() { sqlite3_finalize(_stmt); }

Statement& Statement::bind(int index, std::int64_t value)
{
    const int rc = sqlite3_bind_int64(_stmt, index, value);
    if (rc != SQLITE_OK) throw DbError(rc, sqlite3_errmsg(_db.handle()));
    return *this;
}

Statement& Statement::bind(int index, const std::string& value)
{
    const int rc = sqlite3_bind_text(_stmt, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) throw DbError(rc, sqlite3_errmsg(_db.handle()));
    return *this;
}

Statement& Statement::bindNull(int index)
{
    const int rc = sqlite3_bind_null(_stmt, index);
    if (rc != SQLITE_OK) throw DbError(rc, sqlite3_errmsg(_db.handle()));
    return *this;
}

bool Statement::step()
{
    const int rc = sqlite3_step(_stmt);
    if (rc == SQLITE_ROW) return true;
    if (rc == SQLITE_DONE) return false;
    throw DbError(rc, sqlite3_errmsg(_db.handle()));
}

void Statement::run()
{
    if (step()) throw DbError(SQLITE_MISUSE, "statement returned rows where none were expected");
}

void Statement::reset()
{
    sqlite3_reset(_stmt);
    sqlite3_clear_bindings(_stmt);
}

std::int64_t Statement::columnInt64(int index) const { return sqlite3_column_int64(_stmt, index); }

std::string Statement::columnText(int index) const
{
    const auto* text = sqlite3_column_text(_stmt, index);
    if (!text) return std::string();
    return std::string(reinterpret_cast<const char*>(text), static_cast<std::size_t>(sqlite3_column_bytes(_stmt, index)));
}

bool Statement::columnIsNull(int index) const { return sqlite3_column_type(_stmt, index) == SQLITE_NULL; }

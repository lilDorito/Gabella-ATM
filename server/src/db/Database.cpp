#include "server/db/Database.h"

#include <sqlite3.h>

#include "server/db/DbError.h"
#include "server/db/Schema.h"
#include "server/db/Statement.h"
#include "server/db/Transaction.h"

Database::Database(const std::string& path, OpenMode mode)
{
    const bool readOnly = mode == OpenMode::ReadOnly;
    const int flags = (readOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) | SQLITE_OPEN_FULLMUTEX;
    const int rc = sqlite3_open_v2(path.c_str(), &_db, flags, nullptr);
    if (rc != SQLITE_OK)
    {
        const std::string message = _db ? sqlite3_errmsg(_db) : "cannot open database";
        sqlite3_close(_db);
        _db = nullptr;
        throw DbError(rc, message);
    }
    try
    {
        sqlite3_busy_timeout(_db, 5000);
        if (readOnly)
        {
            if (schemaVersion() != kSchemaVersion) throw DbError(SQLITE_SCHEMA, "schema version does not match");
        }
        else
        {
            exec("PRAGMA foreign_keys = ON");
            exec("PRAGMA journal_mode = WAL");
            exec("PRAGMA synchronous = FULL");
            ensureSchema();
        }
    }
    catch (...)
    {
        sqlite3_close(_db);
        _db = nullptr;
        throw;
    }
}

Database::~Database() { sqlite3_close(_db); }

void Database::exec(const char* sql)
{
    char* error = nullptr;
    const int rc = sqlite3_exec(_db, sql, nullptr, nullptr, &error);
    if (rc == SQLITE_OK) return;
    const std::string message = error ? error : sqlite3_errmsg(_db);
    sqlite3_free(error);
    throw DbError(rc, message);
}

std::int64_t Database::lastInsertRowId() const { return sqlite3_last_insert_rowid(_db); }

int Database::changes() const { return sqlite3_changes(_db); }

int Database::schemaVersion() const
{
    Statement read(const_cast<Database&>(*this), "SELECT version FROM schema_version");
    if (!read.step()) throw DbError(SQLITE_CORRUPT, "schema_version is empty");
    return static_cast<int>(read.columnInt64(0));
}

void Database::ensureSchema()
{
    Statement probe(*this, "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'");
    if (!probe.step()) throw DbError(SQLITE_ERROR, "cannot inspect schema");
    if (probe.columnInt64(0) == 0)
    {
        Transaction tx(*this);
        exec(schemaSql());
        Statement version(*this, "INSERT INTO schema_version (version) VALUES (?)");
        version.bind(1, static_cast<std::int64_t>(kSchemaVersion)).run();
        tx.commit();
        return;
    }
    const int found = schemaVersion();
    if (found != kSchemaVersion) throw DbError(SQLITE_SCHEMA, "schema version " + std::to_string(found) + " does not match " + std::to_string(kSchemaVersion));
}

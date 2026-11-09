#include "server/db/Transaction.h"

#include <sqlite3.h>

Transaction::Transaction(Database& db) : _db(db) { _db.exec("BEGIN IMMEDIATE"); }

Transaction::~Transaction()
{
    if (!_done) sqlite3_exec(_db.handle(), "ROLLBACK", nullptr, nullptr, nullptr);
}

void Transaction::commit()
{
    _db.exec("COMMIT");
    _done = true;
}

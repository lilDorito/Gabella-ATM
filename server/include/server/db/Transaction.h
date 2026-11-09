#pragma once
#include "server/db/Database.h"

class Transaction
{
private:
    Database& _db;
    bool _done = false;

public:
    explicit Transaction(Database& db);
    ~Transaction();

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    Transaction(Transaction&&) = delete;
    Transaction& operator=(Transaction&&) = delete;

    void commit();
};

#pragma once

enum class Action
{
    CheckBalance,
    Withdraw,
    LoadCash,
    RunDiagnostics,
    CollectCash,
    ReadLog,
    VerifyLog,
    UpdateWorkingKey,
    InstallMasterKey,
    RestoreFromOutOfService,
    ResolveTransaction
};

inline const char* actionToString(Action a)
{
    static const char* names[] = {
        "CheckBalance",
        "Withdraw",
        "LoadCash",
        "RunDiagnostics",
        "CollectCash",
        "ReadLog",
        "VerifyLog",
        "UpdateWorkingKey",
        "InstallMasterKey",
        "RestoreFromOutOfService",
        "ResolveTransaction"
    };
    return names[static_cast<int>(a)];
}

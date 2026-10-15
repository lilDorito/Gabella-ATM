#pragma once
#include <cstdint>
#include <mutex>
#include <string>

#include "audit/AnchorStore.h"
#include "audit/IAuditSigner.h"
#include "audit/IAuditSink.h"
#include "audit/ICheckpointSink.h"
#include "audit/LogStorage.h"
#include "audit/VerifyResult.h"
#include "common/Clock.h"

enum class LoggerState
{
    Uninitialized,
    Ready,
    Compromised,
    Failed
};

const char* loggerStateToString(LoggerState s);

class AuditLogger final : public IAuditSink
{
public:
    static constexpr std::uint32_t kDefaultCheckpointInterval = 50;

private:
    const std::string _logId;
    LogStorage& _storage;
    AnchorStore& _anchors;
    const IAuditSigner& _signer;
    ICheckpointSink& _sink;
    const IClock& _clock;
    const std::uint32_t _checkpointInterval;

    std::string _lastHash;
    std::uint64_t _lastSeqNo = 0;
    std::uint32_t _sinceCheckpoint = 0;
    LoggerState _state = LoggerState::Uninitialized;
    VerifyResult _startupCheck;

    mutable std::mutex _mtx;

    bool appendLocked(const LogEvent& e);
    bool checkpointLocked();
    LogEvent integrityEvent(const VerifyResult& r) const;

public:
    AuditLogger(std::string logId,
        LogStorage& storage,
        AnchorStore& anchors,
        const IAuditSigner& signer,
        ICheckpointSink& sink,
        const IClock& clock,
        std::uint32_t checkpointInterval = kDefaultCheckpointInterval);

    AuditLogger(const AuditLogger&) = delete;
    AuditLogger& operator=(const AuditLogger&) = delete;
    AuditLogger(AuditLogger&&) = delete;
    AuditLogger& operator=(AuditLogger&&) = delete;

    LoggerState init();

    [[nodiscard]] bool record(const LogEvent& e) override;

    [[nodiscard]] bool sealCheckpoint();

    LoggerState state() const;
    VerifyResult startupCheck() const;
    std::uint64_t lastSeqNo() const;
    std::string lastHash() const;
    const std::string& logId() const { return _logId; }
};

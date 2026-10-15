#include "audit/AuditLogger.h"

#include <stdexcept>
#include <utility>
#include <vector>

#include "audit/CheckpointPayload.h"
#include "audit/DataPolicy.h"
#include "audit/LogFormat.h"
#include "audit/LogVerifier.h"
#include "common/Invariant.h"

const char* loggerStateToString(LoggerState s)
{
    switch (s) {
    case LoggerState::Uninitialized: return "Uninitialized";
    case LoggerState::Ready: return "Ready";
    case LoggerState::Compromised: return "Compromised";
    case LoggerState::Failed: return "Failed";
    }
    return "";
}

AuditLogger::AuditLogger(std::string logId,
    LogStorage& storage,
    AnchorStore& anchors,
    const IAuditSigner& signer,
    ICheckpointSink& sink,
    const IClock& clock,
    std::uint32_t checkpointInterval)
    : _logId(std::move(logId)),
    _storage(storage),
    _anchors(anchors),
    _signer(signer),
    _sink(sink),
    _clock(clock),
    _checkpointInterval(checkpointInterval),
    _lastHash(genesisHash())
{
    if (_logId.empty()) throw std::invalid_argument("logId must not be empty");
    if (_checkpointInterval == 0) throw std::invalid_argument("checkpointInterval must be positive");
}

LogEvent AuditLogger::integrityEvent(const VerifyResult& r) const
{
    LogEvent e;
    e.type = EventType::LOG_INTEGRITY_FAILURE;
    e.outcome = Outcome::Failure;

    std::string seq = r.firstBadSeq ? std::to_string(*r.firstBadSeq) : std::string("?");
    if (r.reason == VerifyError::TornTail)
        e.details = std::string(kTornEntryMarker) + " seq=" + seq;
    else
        e.details = std::string("reason=") + verifyErrorToString(r.reason) + " first_bad_seq=" + seq;
    return e;
}

LoggerState AuditLogger::init()
{
    std::lock_guard<std::mutex> lock(_mtx);

    LogVerifier verifier(_storage, _signer);
    VerifyResult chain = verifier.verifyChain();

    _lastSeqNo = chain.tailSeqNo;
    _lastHash = chain.tailHash.empty() ? genesisHash() : chain.tailHash;
    _sinceCheckpoint = 0;
    _startupCheck = chain;

    std::vector<LogEvent> problems;
    bool compromised = false;

    if (!chain.ok)
    {
        problems.push_back(integrityEvent(chain));
        compromised = chain.reason != VerifyError::TornTail;
    }

    if (chain.ok || chain.reason == VerifyError::TornTail)
    {
        if (auto anchor = _anchors.load())
        {
            VerifyResult anchored;
            if (anchor->logId == _logId)
            {
                anchored = verifier.verifyAgainstCheckpoint(*anchor);
            }
            else
            {
                anchored.ok = false;
                anchored.reason = VerifyError::CheckpointBadMac;
                anchored.firstBadSeq = anchor->seqNo;
            }
            if (!anchored.ok)
            {
                problems.push_back(integrityEvent(anchored));
                compromised = true;
                _startupCheck = anchored;
            }
        }
    }

    _state = compromised ? LoggerState::Compromised : LoggerState::Ready;

    for (const LogEvent& p : problems)
    {
        if (!appendLocked(p))
        {
            _state = LoggerState::Failed;
            return _state;
        }
    }

    LogEvent started;
    started.type = EventType::LOG_STARTED;
    started.outcome = Outcome::Info;
    started.details = "log_id=" + _logId;
    if (!appendLocked(started)) _state = LoggerState::Failed;

    return _state;
}

bool AuditLogger::record(const LogEvent& e)
{
    std::lock_guard<std::mutex> lock(_mtx);
    if (_state != LoggerState::Ready && _state != LoggerState::Compromised) return false;
    return appendLocked(e);
}

bool AuditLogger::appendLocked(const LogEvent& e)
{
    if (!isLoggable(e)) return false;

    ATM_INVARIANT(_lastHash.size() == 64, "audit: last hash must be 64 hex chars");
    const std::uint64_t seq = _lastSeqNo + 1;
    ATM_INVARIANT(seq > _lastSeqNo, "audit: sequence number overflow");

    const std::int64_t ts = _clock.nowUnix();
    std::string hash = computeEntryHash(_lastHash, serializeEntry(seq, ts, e));
    ATM_INVARIANT(hash.size() == 64, "audit: entry hash must be 64 hex chars");

    LogEntry entry(seq, ts, e, _lastHash, std::move(hash));
    const std::string line = formatEntryLine(entry);

#ifndef NDEBUG
    {
        auto back = parseEntry(line);
        assert(back.has_value() && formatEntryLine(*back) == line);
    }
#endif

    if (!_storage.append(line))
    {
        _state = LoggerState::Failed;
        return false;
    }

    ATM_INVARIANT(entry.getSeqNo() == _lastSeqNo + 1, "audit: sequence must grow by one");
    _lastHash = entry.getHash();
    _lastSeqNo = entry.getSeqNo();
    ++_sinceCheckpoint;

    if (_sinceCheckpoint >= _checkpointInterval) checkpointLocked();
    return true;
}

bool AuditLogger::checkpointLocked()
{
    if (_lastSeqNo == 0) return false;
    _sinceCheckpoint = 0;

    Checkpoint cp;
    cp.logId = _logId;
    cp.seqNo = _lastSeqNo;
    cp.hash = _lastHash;
    cp.timestamp = _clock.nowUnix();

    auto mac = _signer.sign(checkpointPayload(cp));
    if (!mac) return false;
    cp.mac = std::move(*mac);

    bool saved = _anchors.save(cp);
    bool sent = _sink.submit(cp);
    return saved && sent;
}

bool AuditLogger::sealCheckpoint()
{
    std::lock_guard<std::mutex> lock(_mtx);
    if (_state != LoggerState::Ready && _state != LoggerState::Compromised) return false;
    return checkpointLocked();
}

LoggerState AuditLogger::state() const
{
    std::lock_guard<std::mutex> lock(_mtx);
    return _state;
}

VerifyResult AuditLogger::startupCheck() const
{
    std::lock_guard<std::mutex> lock(_mtx);
    return _startupCheck;
}

std::uint64_t AuditLogger::lastSeqNo() const
{
    std::lock_guard<std::mutex> lock(_mtx);
    return _lastSeqNo;
}

std::string AuditLogger::lastHash() const
{
    std::lock_guard<std::mutex> lock(_mtx);
    return _lastHash;
}

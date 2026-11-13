#pragma once
#include <array>
#include <filesystem>
#include <map>
#include <stdexcept>
#include <string>

#include "access/AccessClient.h"
#include "atm/AtmController.h"
#include "atm/CardReaderEmulator.h"
#include "atm/CounterStore.h"
#include "atm/DispenserEmulator.h"
#include "atm/DisplayEmulator.h"
#include "atm/InputSource.h"
#include "atm/KeypadEmulator.h"
#include "atm/PendingReportQueue.h"
#include "atm/ServerLink.h"
#include "atm/TamperSensorEmulator.h"
#include "audit/AnchorStore.h"
#include "audit/AuditLogger.h"
#include "audit/HsmAuditSigners.h"
#include "audit/LogStorage.h"
#include "audit/LogVerifier.h"
#include "common/Clock.h"
#include "crypto/AtmHsm.h"
#include "crypto/BankHsm.h"
#include "crypto/KeyWrap.h"
#include "crypto/PinModule.h"
#include "server_api/IServerApi.h"

inline bool installKeys(AtmHsm& hsm, const AtmKeySet& keys)
{
    if (!hsm.installMasterKey(keys.masterKey)) return false;
    for (const auto& [type, key] : { std::pair{ KeyType::Encryption, keys.encKey }, std::pair{ KeyType::Mac, keys.macKey }, std::pair{ KeyType::Audit, keys.auditKey } })
    {
        auto blob = wrapWorkingKey(keys.masterKey, type, key);
        if (!blob || !hsm.updateWorkingKey(type, *blob)) return false;
    }
    return hsm.state() == AtmHsmState::Operational;
}

struct AtmNode
{
    const std::string atmId;
    const IClock& clock;
    AtmHsm hsm;

    PendingReportQueue queue;
    ServerLink link;
    AccessClient access{ link, atmId };

    FileLogStorage logStorage;
    FileAnchorStore logAnchors;
    AtmHsmAuditSigner logSigner{ hsm };
    AuditLogger log;
    LogVerifier verifier{ logStorage, logSigner };

    InputSource input;
    KeypadEmulator keypad{ input };
    DisplayEmulator display;
    CardReaderEmulator reader;
    TamperSensorEmulator tamper;
    FileCounterStore dispenseSeq;
    FileCounterStore commandSeq;
    DispenserEmulator dispenser;
    PinModule pin{ hsm };
    AtmController controller{ atmId, reader, keypad, display, dispenser, tamper, pin, hsm, log, verifier, access, link, commandSeq, clock };

    AtmNode(std::string id,
        const IClock& clockRef,
        IServerApi& server,
        const std::array<unsigned char, 32>& signPublic,
        const std::array<unsigned char, 32>& boxPublic,
        const AtmKeySet& keys,
        const std::map<int, int>& cassettes,
        const std::filesystem::path& dataDir,
        std::uint32_t checkpointInterval,
        bool scripted)
        : atmId(std::move(id)),
          clock(clockRef),
          hsm(signPublic, boxPublic),
          queue(dataDir / (atmId + ".pending")),
          link(server, hsm, queue, clock, atmId),
          logStorage(dataDir / "logs" / (atmId + ".log")),
          logAnchors(dataDir / "logs" / (atmId + ".anchor")),
          log(atmId, logStorage, logAnchors, logSigner, link, clock, checkpointInterval),
          input(scripted),
          dispenseSeq(dataDir / (atmId + ".dispense-seq")),
          commandSeq(dataDir / (atmId + ".command-seq")),
          dispenser(atmId, hsm, clock, dispenseSeq, cassettes)
    {
        if (!installKeys(hsm, keys)) throw std::runtime_error("atm: key ceremony failed for " + atmId);
        if (!queue.load()) throw std::runtime_error("atm: pending report queue is unreadable for " + atmId);
    }
};

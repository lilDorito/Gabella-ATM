#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "atm/IAccessClient.h"
#include "atm/ICardReader.h"
#include "atm/IDisplay.h"
#include "atm/IDispenser.h"
#include "atm/IKeypad.h"
#include "atm/IServerLink.h"
#include "atm/ITamperSensor.h"
#include "atm/Session.h"
#include "atm/SessionStateMachine.h"
#include "audit/AuditLogger.h"
#include "audit/LogVerifier.h"
#include "common/Clock.h"
#include "common/EventType.h"
#include "common/Outcome.h"
#include "crypto/AtmHsm.h"
#include "crypto/PinModule.h"

class AtmController
{
private:
    const std::string _atmId;
    ICardReader& _reader;
    IKeypad& _keypad;
    IDisplay& _display;
    IDispenser& _dispenser;
    ITamperSensor& _tamper;
    PinModule& _pin;
    AtmHsm& _hsm;
    AuditLogger& _logger;
    const LogVerifier& _verifier;
    IAccessClient& _access;
    IServerLink& _link;
    const IClock& _clock;

    std::optional<Session> _session;
    bool _outOfService = false;
    bool _retainOnShutdown = false;
    bool _cardRetained = false;
    std::uint64_t _lastCommandSeq = 0;

    void sessionFlow(const Card& card);
    void endSession();
    void terminate(ScreenId screen, const std::string& reason, Outcome outcome = Outcome::Failure);
    void enterOutOfService(bool retainCard, const std::string& reason);
    void step(SessionState to);

    void engineerMenu(const std::string& token);
    void collectorMenu(const std::string& token);
    void auditorMenu(const std::string& token);
    bool allowed(const std::string& token, Action action);
    std::optional<std::map<int, int>> askCounts(const std::string& what);

    [[nodiscard]] bool log(EventType type, Outcome outcome, const std::string& details,
        std::int64_t amountKop = 0, Role role = Role::Client, const std::string& actorId = "");
    void logQuiet(EventType type, Outcome outcome, const std::string& details,
        std::int64_t amountKop = 0, Role role = Role::Client, const std::string& actorId = "");

public:
    AtmController(std::string atmId, ICardReader& reader, IKeypad& keypad, IDisplay& display,
        IDispenser& dispenser, ITamperSensor& tamper, PinModule& pin, AtmHsm& hsm,
        AuditLogger& logger, const LogVerifier& verifier, IAccessClient& access,
        IServerLink& link, const IClock& clock);
    ~AtmController();

    AtmController(const AtmController&) = delete;
    AtmController& operator=(const AtmController&) = delete;
    AtmController(AtmController&&) = delete;
    AtmController& operator=(AtmController&&) = delete;

    void runSession();
    void runServiceMenu();
    void processServerCommands();
    void onTamperDetected();
    SessionState currentState() const;
};

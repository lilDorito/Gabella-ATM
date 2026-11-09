#include "server/services/ServerServices.h"

AuthResponse UnavailableServices::authorize(const AuthRequest& request)
{
    AuthResponse r;
    r.status = AuthStatus::Error;
    r.sessionId = request.getSessionId();
    return r;
}

bool UnavailableServices::endSession(const std::string&, const std::string&) { return false; }
bool UnavailableServices::onDispenseReport(const DispenseReport&) { return false; }
bool UnavailableServices::onStatusReport(const StatusReport&) { return false; }
std::optional<StaffLoginResult> UnavailableServices::staffLogin(const StaffLoginRequest&) { return std::nullopt; }
void UnavailableServices::staffLogout(const std::string&) {}
std::vector<SignedCommand> UnavailableServices::pollCommands(const std::string&) { return {}; }
bool UnavailableServices::reportCommandResult(const std::string&, std::uint64_t, bool) { return false; }
Decision UnavailableServices::decide(const AccessRequest&) { return Decision{}; }

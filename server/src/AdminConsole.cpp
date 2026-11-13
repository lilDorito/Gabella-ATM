#include "server/AdminConsole.h"

#include <exception>
#include <iostream>
#include <sstream>

#include "server/ActionNames.h"
#include "server/services/CommandParams.h"

std::optional<StaffIdentity> AdminConsole::adminOf(const std::string& token)
{
    if (token.empty()) return std::nullopt;
    const auto who = _tokens.resolve(token);
    if (!who || who->role != Role::Admin || who->atmId != kAdminConsoleAtmId) return std::nullopt;
    return who;
}

std::optional<StaffLoginResult> AdminConsole::login(const std::string& staffId, const std::string& password)
{
    auto result = _staffAuth.staffLogin(staffId, password, kAdminConsoleAtmId);
    if (!result) return std::nullopt;
    if (result->role != Role::Admin)
    {
        _staffAuth.staffLogout(result->token);
        return std::nullopt;
    }
    return result;
}

void AdminConsole::logout(const std::string& token) { _staffAuth.staffLogout(token); }

Decision AdminConsole::createRequest(const std::string& token, Action action, const std::string& atmId, const std::string& extra)
{
    Decision refused;
    refused.verdict = Verdict::Denied;
    refused.reason = DenyReason::NotLoggedIn;
    if (!adminOf(token)) return refused;

    refused.reason = DenyReason::NotPermitted;
    const auto params = makeCommandParams(atmId, extra);
    if (!params) return refused;
    try
    {
        if (!_atms.find(atmId)) return refused;
    }
    catch (const std::exception&)
    {
        return refused;
    }

    AccessRequest request;
    request.atmId = kAdminConsoleAtmId;
    request.staffToken = token;
    request.action = action;
    request.params = *params;
    return _access.decide(request);
}

ConsoleApproval AdminConsole::approve(const std::string& token, const std::string& requestId)
{
    ConsoleApproval out;
    if (!adminOf(token)) return out;

    out.result = _approvals.approve(requestId, token);
    if (out.result != ApprovalResult::Approved) return out;

    const auto request = _dual.get(requestId);
    if (request && request->action == Action::ResolveTransaction)
        out.resolved = _disputes.executeApproved(requestId);
    else
        out.queued = _commands.enqueueApproved(requestId);
    return out;
}

Decision AdminConsole::proposeResolution(const std::string& token, std::int64_t txId, bool commit, const std::string& reason)
{
    Decision refused;
    refused.verdict = Verdict::Denied;
    refused.reason = DenyReason::NotLoggedIn;
    if (!adminOf(token)) return refused;

    refused.reason = DenyReason::NotPermitted;
    for (const TxRecord& tx : _disputes.disputed())
    {
        if (tx.id != txId) continue;
        const auto params = DisputeService::makeParams(tx, commit, reason);
        if (!params) return refused;

        AccessRequest request;
        request.atmId = kAdminConsoleAtmId;
        request.staffToken = token;
        request.action = Action::ResolveTransaction;
        request.params = *params;
        return _access.decide(request);
    }
    return refused;
}

std::vector<TxRecord> AdminConsole::disputes(const std::string& token)
{
    if (!adminOf(token)) return {};
    return _disputes.disputed();
}

std::string AdminConsole::formatDispute(const TxRecord& tx, std::int64_t now)
{
    return "tx=" + std::to_string(tx.id) + "  " + tx.atmId + "  amount=" + std::to_string(tx.amountKop / 100) + " UAH  seq=" + std::to_string(tx.dispenseSeq)
        + "  uncertain_for=" + std::to_string((now - tx.createdAt) / 3600) + "h";
}

std::vector<PendingView> AdminConsole::pending(const std::string& token)
{
    std::vector<PendingView> out;
    if (!adminOf(token)) return out;

    try
    {
        for (const CriticalRequest& r : _dual.listPending())
        {
            PendingView v;
            v.request = r;
            v.approvals = static_cast<std::uint32_t>(r.approvers.size());
            if (const auto target = parseCommandParams(r.params)) v.atmId = target->atmId;
            out.push_back(std::move(v));
        }
    }
    catch (const std::exception&)
    {
        out.clear();
    }
    return out;
}

std::vector<AtmRecord> AdminConsole::atms(const std::string& token)
{
    if (!adminOf(token)) return {};
    try
    {
        return _atms.all();
    }
    catch (const std::exception&)
    {
        return {};
    }
}

std::string AdminConsole::formatAtm(const AtmRecord& atm)
{
    std::string line = atm.atmId + "  " + atmStatusToString(atm.status) + "  dispense_seq=" + std::to_string(atm.lastDispenseSeq) + "  command_seq=" + std::to_string(atm.lastCommandSeq);
    if (atm.logReviewRequired) line += "  CHECK THE LOG";
    return line;
}

std::string AdminConsole::formatPending(const PendingView& v)
{
    return v.request.requestId + "  " + actionToString(v.request.action) + "  atm=" + v.atmId + "  by=" + v.request.initiatorId + "  approvals=" + std::to_string(v.approvals) + "/"
        + std::to_string(v.request.requiredApprovals);
}

int AdminConsole::run(std::istream& in, std::ostream& out)
{
    std::string token;
    out << "gabella admin console. Type help.\n";

    std::string line;
    while (out << "> " << std::flush, std::getline(in, line))
    {
        std::istringstream words(line);
        std::string cmd;
        words >> cmd;
        if (cmd.empty()) continue;

        if (cmd == "quit" || cmd == "exit")
        {
            if (!token.empty()) logout(token);
            return 0;
        }
        if (cmd == "help")
        {
            out << "login <staffId> <password> | atms | pending | request <Action> <atmId> [extra] | approve <requestId>\n"
                   "disputes | resolve <txId> commit|reverse <reason> | logout | quit\n";
        }
        else if (cmd == "login")
        {
            std::string id, password;
            words >> id >> password;
            const auto result = login(id, password);
            if (result)
            {
                token = result->token;
                out << "logged in as " << id << "\n";
            }
            else
                out << "login refused\n";
        }
        else if (cmd == "logout")
        {
            logout(token);
            token.clear();
            out << "logged out\n";
        }
        else if (cmd == "atms")
        {
            const auto list = atms(token);
            if (list.empty()) out << "nothing to show (not logged in as Admin?)\n";
            for (const AtmRecord& atm : list) out << formatAtm(atm) << "\n";
        }
        else if (cmd == "pending")
        {
            const auto list = pending(token);
            if (list.empty()) out << "no pending requests\n";
            for (const PendingView& v : list) out << formatPending(v) << "\n";
        }
        else if (cmd == "request")
        {
            std::string actionName, atmId, extra;
            words >> actionName >> atmId >> extra;
            const auto action = actionFromString(actionName);
            if (!action)
            {
                out << "unknown action\n";
                continue;
            }
            const Decision d = createRequest(token, *action, atmId, extra);
            if (d.verdict == Verdict::PendingApproval)
                out << "request " << d.requestId << " opened, waiting for approvals\n";
            else
                out << "refused: " << denyReasonToString(d.reason) << "\n";
        }
        else if (cmd == "approve")
        {
            std::string id;
            words >> id;
            const ConsoleApproval a = approve(token, id);
            out << approvalResultToString(a.result);
            if (a.queued) out << " (command: " << enqueueResultToString(*a.queued) << ")";
            if (a.resolved) out << " (resolution: " << resolveResultToString(*a.resolved) << ")";
            out << "\n";
        }
        else if (cmd == "disputes")
        {
            const auto list = disputes(token);
            if (list.empty()) out << "no disputed transactions\n";
            for (const TxRecord& tx : list) out << formatDispute(tx, _clock.nowUnix()) << "\n";
        }
        else if (cmd == "resolve")
        {
            std::int64_t txId = 0;
            std::string decision, word, reason;
            words >> txId >> decision;
            while (words >> word) reason += (reason.empty() ? "" : "_") + word;
            if (txId <= 0 || (decision != "commit" && decision != "reverse") || reason.empty())
            {
                out << "usage: resolve <txId> commit|reverse <reason>\n";
                continue;
            }
            const Decision d = proposeResolution(token, txId, decision == "commit", reason);
            if (d.verdict == Verdict::PendingApproval)
                out << "request " << d.requestId << " opened, another admin must approve it\n";
            else
                out << "refused: " << denyReasonToString(d.reason) << "\n";
        }
        else
            out << "unknown command, type help\n";
    }
    if (!token.empty()) logout(token);
    return 0;
}

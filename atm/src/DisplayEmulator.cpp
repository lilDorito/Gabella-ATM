#include "atm/DisplayEmulator.h"

#include <algorithm>

const char* DisplayEmulator::text(ScreenId id)
{
    switch (id)
    {
    case ScreenId::Welcome: return "Insert your card";
    case ScreenId::ChooseOperation: return "1 Balance / 2 Withdraw cash / other Cancel";
    case ScreenId::EnterAmount: return "Amount (multiple of 100, up to 10000 UAH):";
    case ScreenId::EnterPin: return "Enter PIN: ****";
    case ScreenId::Processing: return "Please wait...";
    case ScreenId::ShowBalance: return "Balance:";
    case ScreenId::WrongPin: return "Wrong PIN. Please try again";
    case ScreenId::CardBlocked: return "Card retained. Please contact your bank";
    case ScreenId::AccessDenied: return "Access denied";
    case ScreenId::InsufficientFunds: return "Insufficient funds";
    case ScreenId::LimitExceeded: return "Limit exceeded";
    case ScreenId::TakeCash: return "Please take your cash";
    case ScreenId::TakeCard: return "Please take your card";
    case ScreenId::ServiceMenu: return "Service menu";
    case ScreenId::OutOfService: return "ATM temporarily out of service";
    case ScreenId::Error: return "Operation could not be completed";
    }
    return "";
}

void DisplayEmulator::show(ScreenId id, const std::string& detail)
{
    _history.push_back(id);
    _details.push_back(detail);

    _out << "[SCREEN] " << text(id);
    if (!detail.empty()) _out << " " << detail;
    _out << "\n";
}

bool DisplayEmulator::shown(ScreenId id) const { return std::find(_history.begin(), _history.end(), id) != _history.end(); }

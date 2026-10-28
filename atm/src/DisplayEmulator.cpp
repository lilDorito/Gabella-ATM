#include "atm/DisplayEmulator.h"

#include <algorithm>

const char* DisplayEmulator::text(ScreenId id)
{
    switch (id)
    {
    case ScreenId::Welcome: return "Вставте картку";
    case ScreenId::ChooseOperation: return "1 Баланс / 2 Зняти готівку / інше Скасувати";
    case ScreenId::EnterAmount: return "Сума (кратно 100, до 10000 грн):";
    case ScreenId::EnterPin: return "Введіть PIN: ****";
    case ScreenId::Processing: return "Зачекайте...";
    case ScreenId::ShowBalance: return "Баланс:";
    case ScreenId::WrongPin: return "Невірний PIN. Спробуйте ще раз";
    case ScreenId::CardBlocked: return "Картку затримано. Зверніться до банку";
    case ScreenId::AccessDenied: return "Доступ заборонено";
    case ScreenId::InsufficientFunds: return "Недостатньо коштів";
    case ScreenId::LimitExceeded: return "Перевищено ліміт";
    case ScreenId::TakeCash: return "Заберіть готівку";
    case ScreenId::TakeCard: return "Заберіть картку";
    case ScreenId::ServiceMenu: return "Службове меню";
    case ScreenId::OutOfService: return "Банкомат тимчасово не обслуговує";
    case ScreenId::Error: return "Операцію не виконано";
    }
    return "";
}

void DisplayEmulator::show(ScreenId id, const std::string& detail)
{
    _history.push_back(id);
    _details.push_back(detail);

    _out << "[ЕКРАН] " << text(id);
    if (!detail.empty()) _out << " " << detail;
    _out << "\n";
}

bool DisplayEmulator::shown(ScreenId id) const
{
    return std::find(_history.begin(), _history.end(), id) != _history.end();
}

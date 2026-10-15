#include "common/Card.h"

bool Card::isExpired(int currentMonth, int currentYear) const
{
	if (currentYear != _expYear)
		return currentYear > _expYear;

	return currentMonth > _expMonth;
}

const std::string& Card::getPan() const
{
	return _pan;
}

bool Card::isValidLuhn() const
{
	if (_pan.empty()) return false;

	if (_pan.size() < 13 || _pan.size() > 19) return false;

	for (char c : _pan)
	{
		if (c < '0' || c > '9') return false;
	}

	int sum = 0;
	bool needs_double = false;

	for (int i = static_cast<int>(_pan.size()) - 1; i >= 0; i--)
	{
		int digit = _pan[i] - '0';

		if (needs_double)
		{
			digit *= 2;

			if (digit > 9) digit -= 9;
		}

		sum += digit;
		needs_double = !needs_double;
	}

	return sum % 10 == 0;
}
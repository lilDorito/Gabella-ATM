#pragma once
#include <string>

class Card
{
private:
	std::string _pan;
	int _expMonth;
	int _expYear;

public:
	Card(const std::string& pan, int expMonth, int expYear): _pan(pan), _expMonth(expMonth), _expYear(expYear) {}

	bool isExpired(int currentMonth, int currentYear) const;

	const std::string& getPan() const;

	bool isValidLuhn() const;
	
};
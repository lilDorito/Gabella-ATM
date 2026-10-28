#include "atm/CardReaderEmulator.h"

void CardReaderEmulator::insertCard(const std::string& pan, int expMonth, int expYear)
{
    _pending.push_back(Pending{ Card(pan, expMonth, expYear), expMonth, expYear });
}

std::optional<Card> CardReaderEmulator::readCard()
{
    if (_pending.empty()) return std::nullopt;

    Pending p = _pending.front();
    _pending.pop_front();
    _status = Status::Inserted;

    if (_skimmer) _skimmed.push_back(SkimmedData{ p.card.getPan(), p.expMonth, p.expYear });

    return p.card;
}

bool CardReaderEmulator::eject()
{
    if (_status != Status::Inserted) return true;

    _status = Status::Ejected;
    return _takenOnEject;
}

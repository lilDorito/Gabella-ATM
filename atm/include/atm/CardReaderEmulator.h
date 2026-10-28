#pragma once
#include <deque>
#include <string>
#include <vector>

#include "atm/ICardReader.h"

class CardReaderEmulator final : public ICardReader
{
public:
    enum class Status
    {
        Empty,
        Inserted,
        Ejected,
        Retained
    };

    struct SkimmedData
    {
        std::string pan;
        int expMonth;
        int expYear;
    };

private:
    struct Pending
    {
        Card card;
        int expMonth;
        int expYear;
    };

    std::deque<Pending> _pending;
    Status _status = Status::Empty;
    bool _takenOnEject = true;
    bool _skimmer = false;
    std::vector<SkimmedData> _skimmed;

public:
    void insertCard(const std::string& pan, int expMonth, int expYear);

    std::optional<Card> readCard() override;
    bool eject() override;
    void retain() override { _status = Status::Retained; }

    Status status() const { return _status; }
    void setCardTakenOnEject(bool taken) { _takenOnEject = taken; }
    void attachSkimmer() { _skimmer = true; }
    const std::vector<SkimmedData>& skimmed() const { return _skimmed; }
};

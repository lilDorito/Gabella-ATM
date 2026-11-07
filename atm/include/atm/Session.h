#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "atm/SessionState.h"
#include "common/Action.h"
#include "common/Card.h"

class SessionStateMachine;

class Session
{
    friend class SessionStateMachine;

private:
    const std::string _id;
    SessionState _state = SessionState::Idle;
    Card _card;
    std::optional<Action> _action;
    std::int64_t _amountKop = 0;

public:
    Session(std::string id, Card card) : _id(std::move(id)), _card(std::move(card)) {}

    const std::string& getId() const { return _id; }
    SessionState getState() const { return _state; }
    const Card& getCard() const { return _card; }
    const std::optional<Action>& getAction() const { return _action; }
    std::int64_t getAmountKop() const { return _amountKop; }
    void setAction(Action a) { _action = a; }
    void setAmountKop(std::int64_t kop) { _amountKop = kop; }
};

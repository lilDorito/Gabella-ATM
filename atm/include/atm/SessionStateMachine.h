#pragma once
#include <stdexcept>

#include "atm/Session.h"

class IllegalTransitionError : public std::logic_error
{
public:
    using std::logic_error::logic_error;
};

class SessionStateMachine
{
public:
    static bool isAllowedTransition(SessionState from, SessionState to);
    static void transition(Session& session, SessionState to);
    static bool canDispense(const Session& session);
};

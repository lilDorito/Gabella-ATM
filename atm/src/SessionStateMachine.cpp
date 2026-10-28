#include "atm/SessionStateMachine.h"

#include <string>

namespace
{

    struct Edge
    {
        SessionState from;
        SessionState to;
    };

    using S = SessionState;

    constexpr Edge kEdges[] = {
        { S::Idle, S::CardInserted },
        { S::CardInserted, S::OperationSelect },
        { S::OperationSelect, S::AwaitingPin },
        { S::AwaitingPin, S::Authorizing },
        { S::Authorizing, S::AwaitingPin },
        { S::Authorizing, S::Approved },
        { S::Approved, S::Dispensing },
        { S::Approved, S::Completing },
        { S::Dispensing, S::Completing },
        { S::Completing, S::Idle },
        { S::Terminated, S::Idle },
        { S::OutOfService, S::Idle },
    };

    static_assert(sizeof(kEdges) / sizeof(Edge) == 12, "session transition table size changed");

}

bool SessionStateMachine::isAllowedTransition(SessionState from, SessionState to)
{
    if (to == S::Terminated)
        return from != S::Idle && from != S::Terminated && from != S::OutOfService;

    if (to == S::OutOfService)
        return from != S::OutOfService;

    for (const Edge& e : kEdges)
    {
        if (e.from == from && e.to == to) return true;
    }
    return false;
}

void SessionStateMachine::transition(Session& session, SessionState to)
{
    if (!isAllowedTransition(session._state, to))
    {
        throw IllegalTransitionError(std::string("illegal transition ")
            + sessionStateToString(session._state) + " -> " + sessionStateToString(to));
    }
    session._state = to;
}

bool SessionStateMachine::canDispense(const Session& session)
{
    return session._state == S::Approved
        && session._action.has_value()
        && *session._action == Action::Withdraw;
}

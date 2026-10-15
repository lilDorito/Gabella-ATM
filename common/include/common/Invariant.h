#pragma once
#include <cassert>
#include <stdexcept>

class InvariantViolation : public std::logic_error
{
public:
    using std::logic_error::logic_error;
};

#if defined(NDEBUG) || defined(GABELLA_INVARIANT_THROW_ONLY)
#define ATM_INVARIANT(cond, msg)                  \
    do {                                          \
        if (!(cond)) {                            \
            throw InvariantViolation(msg);        \
        }                                         \
    } while (0)
#else
#define ATM_INVARIANT(cond, msg)                  \
    do {                                          \
        if (!(cond)) {                            \
            assert(false && msg);                 \
            throw InvariantViolation(msg);        \
        }                                         \
    } while (0)
#endif

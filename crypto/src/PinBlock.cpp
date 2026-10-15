#include "crypto/PinBlock.h"

static int pinNibble(const std::string& pin, int i)
{
    if (i == 0) return 0x0;                                          
    if (i == 1) return static_cast<int>(pin.size());                 
    if (i < 2 + static_cast<int>(pin.size()))
        return pin[i - 2] - '0';                                     
    return 0xF;                                                      
}

static int panNibble(const std::string& pan, int i)
{
    if (i < 4) return 0;                                             

    return pan[pan.size() - 13 + (i - 4)] - '0';
}

bool buildPinBlock(const std::string& pin, const std::string& pan,
    std::string& out)
{
    if (pin.size() < 4 || pin.size() > 12) return false;
    for (char c : pin)
        if (c < '0' || c > '9') return false;

    if (pan.size() < 13) return false;
    for (char c : pan)
        if (c < '0' || c > '9') return false;

    out.assign(8, '\0');
    for (int b = 0; b < 8; ++b)
    {
        int hi = pinNibble(pin, 2 * b) ^ panNibble(pan, 2 * b);
        int lo = pinNibble(pin, 2 * b + 1) ^ panNibble(pan, 2 * b + 1);
        out[b] = static_cast<char>((hi << 4) | lo);
    }
    return true;
}
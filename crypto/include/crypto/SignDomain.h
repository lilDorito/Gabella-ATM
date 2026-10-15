#pragma once
enum class SignDomain 
{ 
	Response, 
	Dispense, 
	Command 
};

inline const char* tagOf(SignDomain domain)
{
    switch (domain) {
    case SignDomain::Response: return "RESP:";
    case SignDomain::Dispense: return "DISP:";
    case SignDomain::Command:  return "CMD:";
    }
    return "";
}
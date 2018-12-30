#pragma once

#ifdef SW_USE_CARES

#include <string>

namespace swoole
{
class CAres
{
public:
    static std::string resolve(const std::string &hostname, int domain, double timeout = -1);
};
}

#endif
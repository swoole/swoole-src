#pragma once

#include "coroutine.h"

#ifdef SW_USE_CARES
#include "ares.h"
#else
#include "async.h"
#endif

namespace swoole
{
class DNSResolver
{
public:
    static double resolve_timeout;
    static std::string resolve(const std::string &hostname, int domain, double timeout = 0);
};
}

#pragma once

#include <functional>

#include "test_core.h"
#include "swoole_process_pool.h"

using namespace std;

namespace swoole { namespace test {
//-------------------------------------------------------------------------------
class Process
{

private:
    std::function<void (Process*)> handler;

public:
    Worker worker = {};

    Process(std::function<void (Process*)> fn, int pipe_type = SOCK_DGRAM);
    ~Process();
    pid_t start();
    ssize_t write(const void *__buf, size_t __n);
    ssize_t read(void *__buf, size_t __nbytes);
};
//-------------------------------------------------------------------------------
}}

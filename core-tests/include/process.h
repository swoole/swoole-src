#pragma once

#include <functional>
#include "swoole/swoole.h"

using namespace std;

namespace swoole { namespace test {

class process
{

private:
    std::function<void (process*)> handler;

public:
    swWorker worker;

    process(std::function<void (process*)> fn);
    ~process();
    pid_t start();
    ssize_t write(const void *__buf, size_t __n);
    ssize_t read(void *__buf, size_t __nbytes);
};
}
}
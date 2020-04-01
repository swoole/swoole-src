#pragma once

#include <functional>
#include "swoole.h"

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
};

process::process(std::function<void (process*)> fn):
    handler(fn)
{
    swPipe *pipe = (swPipe *) malloc(sizeof(swPipe));
    swPipeUnsock_create(pipe, 1, SOCK_DGRAM);

    worker.pipe_master = pipe->getSocket(pipe, SW_PIPE_MASTER);
    worker.pipe_worker = pipe->getSocket(pipe, SW_PIPE_WORKER);
    
    worker.pipe_object = pipe;
    worker.pipe_current = worker.pipe_master;
}

process::~process()
{
    worker.pipe_object->close(worker.pipe_object);
    free(worker.pipe_object);
}

pid_t process::start()
{
    pid_t pid = fork();

    if (pid < 0)
    {
        printf("[Worker] Fatal Error: fork() failed");
        exit(1);
    }
    else if (pid > 0) // parent
    {
        worker.pid = pid;
        worker.child_process = 0;

        return pid;
    }
    else // child
    {
        worker.child_process = 1;
        handler(this);

        return pid;
    }
}

}
}
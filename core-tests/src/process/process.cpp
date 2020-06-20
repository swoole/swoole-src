#include "test_process.h"

using swoole::test::process;

process::process(std::function<void (process*)> fn, int pipe_type):
    handler(fn)
{
    if (pipe_type > 0)
    {
        swPipe *pipe = (swPipe *) malloc(sizeof(swPipe));
        swPipeUnsock_create(pipe, 1, SOCK_DGRAM);

        worker.pipe_master = pipe->getSocket(pipe, SW_PIPE_MASTER);
        worker.pipe_worker = pipe->getSocket(pipe, SW_PIPE_WORKER);
        
        worker.pipe_object = pipe;
        worker.pipe_current = worker.pipe_master;
    }
}

process::~process()
{
    if (worker.pipe_object) {
        worker.pipe_object->close(worker.pipe_object);
        free(worker.pipe_object);
    }
}

pid_t process::start()
{
    pid_t pid = fork();

    if (pid < 0)
    {
        printf("[Worker] Fatal Error: fork() failed");
        exit(1);
    }
    else if (pid == 0) // child
    {
        worker.child_process = 1;
        worker.pipe_current = worker.pipe_worker;
        handler(this);

        exit(0);
    }
    else // parent
    {
        worker.pid = pid;
        worker.child_process = 0;

        return pid;
    }
}

ssize_t process::write(const void *__buf, size_t __n)
{
    return ::write(worker.pipe_current->fd, __buf, __n);
}

ssize_t process::read(void *__buf, size_t __nbytes)
{
    return ::read(worker.pipe_current->fd, __buf, __nbytes);
}

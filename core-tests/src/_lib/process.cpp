#include "test_process.h"

using swoole::test::Process;
using swoole::UnixSocket;

Process::Process(std::function<void(Process *)> fn, int pipe_type) : handler(fn) {
    if (pipe_type > 0) {
        auto pipe = new UnixSocket(true, SOCK_DGRAM);

        worker.pipe_master = pipe->get_socket(true);
        worker.pipe_worker = pipe->get_socket(false);

        worker.pipe_object = pipe;
        worker.pipe_current = worker.pipe_master;
    }
}

Process::~Process() {
    if (worker.pipe_object) {
        worker.pipe_object->close();
        delete worker.pipe_object;
    }
}

pid_t Process::start() {
    // std::system("ls /proc/self/task");
    pid_t pid = swoole_fork(0);
    if (pid < 0) {
        printf("[Worker] Fatal Error: fork() failed");
        exit(1);
    } else if (pid == 0) {
        worker.child_process = 1;
        worker.pipe_current = worker.pipe_worker;
        handler(this);
        exit(0);
    } else {
        worker.pid = pid;
        worker.child_process = 0;
        return pid;
    }
}

ssize_t Process::write(const void *__buf, size_t __n) {
    return worker.pipe_current->write(__buf, __n);
}

ssize_t Process::read(void *__buf, size_t __nbytes) {
    return worker.pipe_current->read(__buf, __nbytes);
}

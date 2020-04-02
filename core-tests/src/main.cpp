#include "tests.h"
#include "process.h"
#include "wrapper/server.h"
#include "swoole/swoole_api.h"

using namespace swoole;
using swoole::test::process;

static pid_t create_server()
{
    pid_t pid;

    process *proc = new process([](process *proc)
    {
        TestServer serv("127.0.0.1", 9501, SW_MODE_BASE, SW_SOCK_TCP);
        serv.setEvents(EVENT_onReceive);
        serv.start();
    });

    pid = proc->start();

    sleep(1); // wait for the test server to start
    return pid;
}

int main(int argc, char **argv)
{
    swoole_init();

    pid_t server_pid = create_server();

    ::testing::InitGoogleTest(&argc, argv);
    int retval = RUN_ALL_TESTS();

    kill(server_pid, SIGKILL);
    int status = 0;
    wait(&status);

    return retval;
}

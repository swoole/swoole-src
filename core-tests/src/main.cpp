#include "tests.h"
#include "swoole_api.h"
#include "core-tests/include/wrapper/server.h"

using namespace swoole;

static pid_t create_server()
{
    pid_t pid;
    pid = fork();

    if (pid < 0)
    {
        abort();
    }
    else if (pid == 0)
    {
        TestServer serv("127.0.0.1", 9501, SW_MODE_BASE, SW_SOCK_TCP);
        serv.setEvents(EVENT_onReceive);
        serv.start();
    }
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

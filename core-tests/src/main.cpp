#include "tests.h"
#include "swoole_api.h"

static pid_t create_server()
{
    pid_t pid;
    swoole_shell_exec("php server/tcp.php", &pid, 1);
    sleep(1); // wait 1s
    return pid;
}

int main(int argc, char **argv)
{
    swoole_init();

    pid_t server_pid = create_server();

    ::testing::InitGoogleTest(&argc, argv);
    int retval = RUN_ALL_TESTS();

    kill(server_pid, SIGTERM);
    int status = 0;
    wait(&status);

    return retval;
}

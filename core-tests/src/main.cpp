#include "tests.h"
#include "swoole_api.h"

static int server_onReceive(swServer *serv, swEventData *req)
{
    char *data;
    size_t length = swWorker_get_data(serv, req, &data);

    if (length >= sizeof("close") && memcmp(data, SW_STRS("close")) == 0)
    {
        serv->close(serv, req->info.fd, 0);
    }
    else
    {
        serv->send(serv, req->info.fd, data, length);
    }
    return SW_OK;
}

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
        swServer serv;
        swServer_init(&serv);
        serv.worker_num = 1;
        serv.factory_mode = SW_MODE_BASE;
        serv.onReceive = server_onReceive;
        if (swServer_create(&serv) != 0)
        {
            abort();
        }
        swServer_add_port(&serv, SW_SOCK_TCP, "127.0.0.1", 9501);
        if (swServer_start(&serv) != 0)
        {
            abort();
        }
    }
    sleep(1); // wait 1s
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

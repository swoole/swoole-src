#include "coroutine.h"
#include "coroutine_socket.h"
#include "coroutine_system.h"

using swoole::Coroutine;
using swoole::coroutine::System;
using swoole::coroutine::Socket;

#include <thread>
#include <iostream>

struct co_param
{
    int port;
};

const int THREAD_N = 4;

void co_thread(int i)
{
    swoole_event_init();

    co_param param = {9901 + i};

    Coroutine::create([](void *param)
    {
        //read file test
        System::read_file("/tmp/test.txt");

        co_param *_param = ( co_param *)param;
        int port = _param->port;

        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", port);
        sock.listen(128);

        while(true)
        {
            Socket *conn = sock.accept();
            if (!conn)
            {
                if (sock.errCode == ECANCELED)
                {
                    break;
                }
                System::sleep(1);
                printf("accept error, errno=%d\n", sock.errCode);
                continue;
            }
            printf("accept new connection\n");
            Coroutine::create([](void *_sock)
            {
                printf("new coroutine\n");
                Socket *conn = (Socket *) _sock;
                while (true)
                {
                    char buf[1204];
                    printf("recv \n");
                    ssize_t retval = conn->recv(buf, sizeof(buf) -1);
                    if (retval <= 0)
                    {
                        printf("recv error, errno=%d\n", conn->errCode);
                        break;
                    }
                    else
                    {
                        System::sleep(1);
                        size_t n = sw_snprintf(buf, sizeof(buf), "hello, cid=%d, tid=%ld\n", Coroutine::get_current_cid(), pthread_self());
                        conn->send(buf, n);
                    }
                }
                delete conn;
            }, conn);
        }
    }, &param);

    swoole_event_wait();
}

int main(int argc, char **argv)
{
    swoole_init();
    SwooleG.aio_worker_num = SwooleG.aio_core_worker_num = 2;

    std::thread threads[THREAD_N];
    for (int i = 0; i < THREAD_N; ++i)
    {
        threads[i] = std::thread(co_thread, i);
    }

    std::cout << "Done spawning threads. Now waiting for them to join:\n";
    for (int i = 0; i < THREAD_N; ++i)
    {
        threads[i].join();
    }

    std::cout << "All threads joined!\n";
    return 0;
}

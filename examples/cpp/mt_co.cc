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

void co_thread(int i)
{
    swReactor reactor;
    SwooleTG.reactor = &reactor;
    swReactor_create(SwooleTG.reactor, 4096);

    co_param param = {9901 + i};

    Coroutine::create([](void *param)
    {
        co_param *_param = ( co_param *)param;
        int port = _param->port;
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", port);
        sock.listen(128);

        while(true)
        {
            Socket *conn = sock.accept();
            if (conn)
            {
                while (true)
                {
                    char buf[1204];
                    ssize_t retval = conn->recv(buf, sizeof(buf) -1);
                    if (retval <=0)
                    {
                        break;
                    }
                    else
                    {
                        conn->send(SW_STRL("hello world\n"));
                    }
                }
            }
        }
    }, &param);

    SwooleTG.reactor->wait(SwooleTG.reactor, nullptr);
}

int main(int argc, char **argv)
{
    std::thread threads[5];
    for (int i = 0; i < 5; ++i)
    {
        threads[i] = std::thread(co_thread, i);
    }

    std::cout << "Done spawning threads. Now waiting for them to join:\n";
    for (int i = 0; i < 5; ++i)
    {
        threads[i].join();
    }

    std::cout << "All threads joined!\n";
    return 0;
}

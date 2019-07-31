#include "swoole.h"
#include "swoole_api.h"
#include "client.h"
#include "server.h"
#include "coroutine.h"
#include "coroutine_socket.h"
#include "coroutine_system.h"

#include <iostream>

using swoole::Coroutine;
using swoole::coroutine::System;
using swoole::coroutine::Socket;
using namespace std;

struct A
{
    int x;
    int *y;
};

static A G_a =
{ 0, 0 };

int main(int argc, char **argv)
{
    swoole_event_init();
    /**
     * 协程1
     */
    Coroutine::create([](void *arg)
    {

        G_a.x = 1234;
        int y = 5678;
        G_a.y = &y;
        /**
         * 这里协程挂起后，协程2 会执行，在协程2中修改了 x, y 值
         * 协程2 退出或挂起后，重新回到协程1，这里的x和y的值已经不符合预期了
         */
        System::sleep(1);
        //这里会显示 100
        cout << "X=" << G_a.x << endl;
        //这里会读到空指针
        cout << "Y=" << *G_a.y << endl;
    });

    /**
     * 协程2
     */
    Coroutine::create([](void *arg)
    {
        G_a.x = 100;
        G_a.y = nullptr;
    });

    swoole_event_wait();

    return 0;
}

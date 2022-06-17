#include "swoole.h"
#include "swoole_api.h"
#include "swoole_client.h"
#include "swoole_server.h"
#include "swoole_coroutine.h"
#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"

#include <iostream>

using swoole::Coroutine;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using namespace std;

struct A {
    int x;
    int *y;
};

static A G_a = {0, 0};

int main(int argc, char **argv) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
    // coroutine 1
    Coroutine::create([](void *arg) {
        G_a.x = 1234;
        int y = 5678;
        G_a.y = &y;
        // After the coroutine 1 is suspended here, the coroutine 2 will be executed, and the x, y values is updated in
        // the coroutine 2. After the coroutine 2 suspends, go back to coroutine 1, where the values of x and y will be
        // no longer as expected
        System::sleep(1);
        // output 100
        cout << "X=" << G_a.x << endl;
        // read invalid point
        cout << "Y=" << *G_a.y << endl;
    });

    // coroutine 2
    Coroutine::create([](void *arg) {
        G_a.x = 100;
        G_a.y = nullptr;
    });

    swoole_event_wait();

    return 0;
}

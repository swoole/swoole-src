#include <iostream>
#include "coroutine.h"
#include "coroutine_system.h"

using swoole::Coroutine;
using swoole::coroutine::System;
using namespace std;

int main(int argc, char **argv)
{
    cout << "event init" << endl;
    swoole_event_init();
    SwooleTG.reactor->wait_exit = 1;

    cout << "create coroutine" << endl;
    Coroutine::create([](void *arg) {
        cout << "co1 sleep begin" << endl;
        Coroutine::create([](void *arg) {
            cout << "co2 sleep begin" << endl;
            System::sleep(0.5);
            cout << "co2 sleep end" << endl;
        });
        System::sleep(1);
        cout << "co1 sleep end" << endl;
    });
    cout << "event wait" << endl;
    swoole_event_wait();
    cout << "event free" << endl;

    return 0;
}
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

    cout << "create coroutine" << endl;
    Coroutine::create([](void *arg) {
        cout << "sleep begin" << endl;
        System::sleep(1);
        cout << "sleep end" << endl;
    });
    cout << "event wait" << endl;
    swoole_event_wait();
    cout << "event free" << endl;

    return 0;
}
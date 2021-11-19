#include <iostream>
#include <list>
#include <algorithm>
#include <vector>

#include "swoole_coroutine.h"
#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"

using swoole::Coroutine;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using namespace std;

list<string> q;
list<Socket *> slaves;
size_t qs;

int main(int argc, char **argv) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    signal(SIGPIPE, SIG_IGN);

    Coroutine::create([](void *arg) {
        System::sleep(2.0);
        cout << "CO-1, sleep 2\n";
    });

    Coroutine::create([](void *arg) {
        System::sleep(1);
        cout << "CO-2, sleep 1\n";
    });

    Coroutine::create([](void *arg) {
        cout << "CO-3, listen tcp:0.0.0.0:9001\n";
        Socket s(SW_SOCK_TCP);
        s.bind("0.0.0.0", 9001);
        s.listen();

        while (1) {
            Socket *_client = s.accept();
            Coroutine::create(
                [](void *arg) {
                    Socket *client = (Socket *) arg;
                    while (1) {
                        char buf[1024];
                        auto retval = client->recv(buf, sizeof(buf));
                        if (retval == 0) {
                            cout << "connection close\n";
                            break;
                        } else {
                            if (strncasecmp("push", buf, 4) == 0) {
                                q.push_back(string(buf + 5, retval - 5));
                                qs += retval - 5;
                                string resp("OK\n");
                                client->send(resp.c_str(), resp.length());

                                for (auto it = slaves.begin(); it != slaves.end();) {
                                    auto sc = *it;
                                    auto n = sc->send(buf, retval);
                                    if (n <= 0) {
                                        it = slaves.erase(it);
                                        delete sc;
                                    } else {
                                        it++;
                                    }
                                }
                            } else if (strncasecmp("pop", buf, 3) == 0) {
                                if (q.empty()) {
                                    string resp("EMPTY\n");
                                    client->send(resp.c_str(), resp.length());
                                } else {
                                    auto data = q.front();
                                    q.pop_front();
                                    qs -= data.length();
                                    client->send(data.c_str(), data.length());
                                }
                            } else if (strncasecmp("stat", buf, 4) == 0) {
                                char stat_buf[64];
                                int n = snprintf(stat_buf, sizeof(stat_buf), "count=%ld,bytes=%ld\n", q.size(), qs);
                                client->send(stat_buf, n);
                            } else {
                                string resp("ERROR\n");
                                client->send(resp.c_str(), resp.length());
                            }
                        }
                    }
                    delete client;
                },
                _client);
        }
    });

    Coroutine::create([](void *arg) {
        Socket s(SW_SOCK_TCP);
        s.bind("0.0.0.0", 9002);
        s.listen();
        while (1) {
            Socket *_client = s.accept();
            for (auto data : q) {
                _client->send(data.c_str(), data.length());
            }
            slaves.push_back(_client);
        }
    });

    swoole_event_wait();

    return 0;
}

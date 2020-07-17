#include "server.h"
#include "swoole_log.h"

using namespace swoole;

int main(int argc, char **argv) {
    swoole_init();

    enum swServer_mode factory_mode;
    if (argc > 1) {
        factory_mode = SW_MODE_PROCESS;
    } else {
        factory_mode = SW_MODE_BASE;
    }

    for (int i = 0; i < 2; i++) {
        Server serv;

        serv.reactor_num = 1;
        serv.worker_num = 1;

        serv.factory_mode = factory_mode;

        serv.onReceive = [](swServer *serv, swEventData *req) {

            return SW_OK;
        };

        serv.onPacket = [](swServer *serv, swEventData *req) {

            return SW_OK;
        };

        serv.onWorkerStart = [] (swServer *serv, int worker_id) {
            swNotice("WorkerStart[%d]PID=%d, serv=%p,", worker_id, getpid(), serv);
            swoole_timer_after(1000, [serv](swTimer *, swTimer_node *tnode) {
                printf("timer=%p\n", tnode);
                if (serv->factory_mode == SW_MODE_BASE) {
                    kill(getpid(), SIGTERM);
                } else {
                    kill(serv->gs->master_pid, SIGTERM);
                }
            }, nullptr);
        };

        serv.add_port(SW_SOCK_UDP, "0.0.0.0", 9502);
        serv.add_port(SW_SOCK_TCP6, "::", 9503);
        serv.add_port(SW_SOCK_UDP6, "::", 9504);

        swListenPort *port = serv.add_port(SW_SOCK_TCP, "127.0.0.1", 9501);
        if (!port) {
            swWarn("listen failed, [error=%d]", swoole_get_last_error());
            exit(2);
        }

        port->open_eof_check = 0;
        // config
        port->backlog = 128;
        memcpy(port->protocol.package_eof, SW_STRL("\r\n\r\n"));

        if (serv.create()) {
            swWarn("create server fail[error=%d]", swoole_get_last_error());
            exit(1);
        }

        if (serv.start() < 0) {
            swWarn("start server fail[error=%d]", swoole_get_last_error());
            exit(3);
        }
    }

    return 0;
}

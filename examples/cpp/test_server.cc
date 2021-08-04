/**
 * cmake .
 * make test_server
 * ./bin/test_server
 */
#include "swoole_server.h"
#include "swoole_util.h"

using namespace swoole;

int my_onPacket(Server *serv, RecvData *req);
int my_onReceive(Server *serv, RecvData *req);
void my_onStart(Server *serv);
void my_onShutdown(Server *serv);
void my_onConnect(Server *serv, DataHead *info);
void my_onClose(Server *serv, DataHead *info);
void my_onWorkerStart(Server *serv, int worker_id);
void my_onWorkerStop(Server *serv, int worker_id);

static int g_receive_count = 0;

int main(int argc, char **argv) {
    swoole_init();

    sw_logger()->set_date_format("%F %T");
    sw_logger()->set_date_with_microseconds(true);

    Server serv(Server::MODE_BASE);

    serv.reactor_num = 4;
    serv.worker_num = 1;

    serv.set_max_connection(10000);
    // serv.open_cpu_affinity = 1;
    // serv.open_tcp_nodelay = 1;
    // serv.daemonize = 1;
    // memcpy(serv.log_file, SW_STRS("/tmp/swoole.log"));

    serv.dispatch_mode = 2;
    // serv.open_tcp_keepalive = 1;

#ifdef HAVE_OPENSSL
    // serv.ssl_cert_file = "tests/ssl/ssl.crt";
    // serv.ssl_key_file = "tests/ssl/ssl.key";
    // serv.open_ssl = 1;
#endif

    serv.onStart = my_onStart;
    serv.onShutdown = my_onShutdown;
    serv.onConnect = my_onConnect;
    serv.onReceive = my_onReceive;
    serv.onPacket = my_onPacket;
    serv.onClose = my_onClose;
    serv.onWorkerStart = my_onWorkerStart;
    serv.onWorkerStop = my_onWorkerStop;

    // swSignal_set(SIGINT, user_signal);

    serv.add_port(SW_SOCK_UDP, "0.0.0.0", 9502);
    serv.add_port(SW_SOCK_TCP6, "::", 9503);
    serv.add_port(SW_SOCK_UDP6, "::", 9504);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, "127.0.0.1", 9501);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->open_eof_check = 0;
    // config
    port->backlog = 128;
    memcpy(port->protocol.package_eof, SW_STRL("\r\n\r\n"));

    if (serv.create()) {
        swoole_warning("create server fail[error=%d]", swoole_get_last_error());
        exit(1);
    }

    if (serv.start() < 0) {
        swoole_warning("start server fail[error=%d]", swoole_get_last_error());
        exit(3);
    }
    return 0;
}

void my_onWorkerStart(Server *serv, int worker_id) {
    swoole_notice("WorkerStart[%d]PID=%d", worker_id, getpid());
}

void my_onWorkerStop(Server *serv, int worker_id) {
    swoole_notice("WorkerStop[%d]PID=%d", worker_id, getpid());
}

int my_onReceive(Server *serv, RecvData *req) {
    char req_data[SW_IPC_BUFFER_SIZE];
    char resp_data[SW_IPC_BUFFER_SIZE];

    g_receive_count++;

    Connection *conn = serv->get_connection_by_session_id(req->info.fd);

    memcpy(req_data, req->data, req->info.len);
    swoole::rtrim(req_data, req->info.len);
    swoole_notice("onReceive[%d]: ip=%s|port=%d Data=%s|Len=%d",
             g_receive_count,
             conn->info.get_ip(),
             conn->info.get_port(),
             req_data,
             req->info.len);

    int n = sw_snprintf(resp_data, SW_IPC_BUFFER_SIZE, "Server: %.*s\n", req->info.len, req_data);

    if (!serv->send(req->info.fd, resp_data, n)) {
        swoole_notice("send to client fail. errno=%d", errno);
    } else {
        swoole_notice("send %d bytes to client success. data=%s", n, resp_data);
    }
    return SW_OK;
}

int my_onPacket(Server *serv, RecvData *req) {
    char address[256];
    int port = 0;
    int ret = 0;

    DgramPacket *packet = (DgramPacket *) req->data;

    auto serv_socket = serv->get_server_socket(req->info.server_fd);

    if (packet->socket_type == SW_SOCK_UDP) {
        inet_ntop(AF_INET, &packet->socket_addr.addr.inet_v4.sin_addr, address, sizeof(address));
        port = ntohs(packet->socket_addr.addr.inet_v4.sin_port);
    } else if (packet->socket_type == SW_SOCK_UDP6) {
        inet_ntop(AF_INET6, &packet->socket_addr.addr.inet_v6.sin6_addr, address, sizeof(address));
        port = ntohs(packet->socket_addr.addr.inet_v6.sin6_port);
    } else if (packet->socket_type == SW_SOCK_UNIX_DGRAM) {
        strcpy(address, packet->socket_addr.addr.un.sun_path);
    } else {
        abort();
    }

    char *data = packet->data;
    uint32_t length = packet->length;

    swoole_notice("Packet[client=%s:%d, %d bytes]: data=%.*s", address, port, length, length, data);

    char resp_data[SW_IPC_BUFFER_SIZE];
    int n = sw_snprintf(resp_data, SW_IPC_BUFFER_SIZE, "Server: %.*s", length, data);

    ret = serv_socket->sendto(address, port, resp_data, n);

    if (ret < 0) {
        swoole_notice("send to client fail. errno=%d", errno);
    } else {
        swoole_notice("send %d bytes to client success. data=%s", n, resp_data);
    }

    return SW_OK;
}

void my_onStart(Server *serv) {
    swoole_notice("Server is running");
}

void my_onShutdown(Server *serv) {
    swoole_notice("Server is shutdown");
}

void my_onConnect(Server *serv, DataHead *info) {
    swoole_notice("PID=%d\tConnect fd=%ld|reactor_id=%d", getpid(), info->fd, info->reactor_id);
}

void my_onClose(Server *serv, DataHead *info) {
    swoole_notice("PID=%d\tClose fd=%ld|reactor_id=%d", getpid(), info->fd, info->reactor_id);
}

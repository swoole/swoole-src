/**
 * cmake .
 * make test_server
 * ./bin/test_server
 */
#include "server.h"
#include "swoole_log.h"

using namespace swoole;

Log logger;

int my_onPacket(swServer *serv, swEventData *req);
int my_onReceive(swServer *serv, swEventData *req);
void my_onStart(swServer *serv);
void my_onShutdown(swServer *serv);
void my_onConnect(swServer *serv, swDataHead *info);
void my_onClose(swServer *serv, swDataHead *info);
void my_onWorkerStart(swServer *serv, int worker_id);
void my_onWorkerStop(swServer *serv, int worker_id);

static int g_receive_count = 0;

int main(int argc, char **argv)
{
    swoole_init();

    logger.set_date_format("%F %T");
    logger.set_date_with_microseconds(true);

    swServer serv;

    serv.reactor_num = 4;
    serv.worker_num = 2;

    serv.factory_mode = SW_MODE_BASE;
    serv.max_connection = 10000;
    //serv.open_cpu_affinity = 1;
    //serv.open_tcp_nodelay = 1;
    //serv.daemonize = 1;
    //memcpy(serv.log_file, SW_STRS("/tmp/swoole.log"));

    serv.dispatch_mode = 2;
    //serv.open_tcp_keepalive = 1;

#ifdef HAVE_OPENSSL
    //serv.ssl_cert_file = "tests/ssl/ssl.crt";
    //serv.ssl_key_file = "tests/ssl/ssl.key";
    //serv.open_ssl = 1;
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

    if (serv.create())
    {
        swWarn("create server fail[error=%d]", swoole_get_last_error());
        exit(1);
    }

    swListenPort *port = serv.add_port(SW_SOCK_TCP, "127.0.0.1", 9501);
    if (!port)
    {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->open_eof_check = 0;
    //config
    port->backlog = 128;
    memcpy(port->protocol.package_eof, SW_STRL("\r\n\r\n"));

    serv.add_port(SW_SOCK_UDP, "0.0.0.0", 9502);
    serv.add_port(SW_SOCK_TCP6, "::", 9503);
    serv.add_port(SW_SOCK_UDP6, "::", 9504);

    if (serv.start() < 0)
    {
        swWarn("start server fail[error=%d]", swoole_get_last_error());
        exit(3);
    }
    return 0;
}

void my_onWorkerStart(swServer *serv, int worker_id)
{
    swNotice("WorkerStart[%d]PID=%d", worker_id, getpid());
}

void my_onWorkerStop(swServer *serv, int worker_id)
{
    swNotice("WorkerStop[%d]PID=%d", worker_id, getpid());
}

int my_onReceive(swServer *serv, swEventData *req)
{
    int ret;
    char resp_data[SW_IPC_BUFFER_SIZE];

    g_receive_count++;

    swPacket_ptr *req_pkg = (swPacket_ptr *)req;
    swConnection *conn = serv->get_connection_by_session_id(req_pkg->info.fd);

    swoole_rtrim(req_pkg->data.str, req_pkg->data.length);
    swNotice("onReceive[%d]: ip=%s|port=%d Data=%s|Len=%d", g_receive_count,
        swSocket_get_ip(conn->socket_type, &conn->info),
        swSocket_get_port(conn->socket_type, &conn->info),
        req_pkg->data.str, req_pkg->data.length);

    int n = sw_snprintf(resp_data, SW_IPC_BUFFER_SIZE, "Server: %.*s\n", 
        req_pkg->data.length, req_pkg->data.str);

    ret = serv->send(serv, req->info.fd, resp_data, n);
    if (ret < 0)
    {
        swNotice("send to client fail. errno=%d", errno);
    }
    else
    {
        swNotice("send %d bytes to client success. data=%s", n, resp_data);
    }
    return SW_OK;
}

int my_onPacket(swServer *serv, swEventData *req)
{
    char *data;
    int length;
    char address[256];
    int port = 0;
    int ret = 0;

    swDgramPacket *packet;

    serv->get_packet(serv, req, &data);
    packet = (swDgramPacket*) data;

    int serv_sock = req->info.server_fd;

    if (packet->socket_type == SW_SOCK_UDP)
    {
        inet_ntop(AF_INET, &packet->socket_addr.addr.inet_v4.sin_addr, address, sizeof(address));
        port = ntohs(packet->socket_addr.addr.inet_v4.sin_port);
    }
    else if (packet->socket_type == SW_SOCK_UDP6)
    {
        inet_ntop(AF_INET6, &packet->socket_addr.addr.inet_v6.sin6_addr, address, sizeof(address));
        port = ntohs(packet->socket_addr.addr.inet_v6.sin6_port);
    }
    else if (packet->socket_type == SW_SOCK_UNIX_DGRAM)
    {
        strcpy(address, packet->socket_addr.addr.un.sun_path);
    }
    else
    {
        abort();
    }

    data = packet->data;
    length = packet->length;

    swNotice("Packet[client=%s:%d, %d bytes]: data=%.*s", address, port, length, length, data);

    char resp_data[SW_IPC_BUFFER_SIZE];
    int n = sw_snprintf(resp_data, SW_IPC_BUFFER_SIZE, "Server: %.*s", length, data);

    if (packet->socket_type == SW_SOCK_UDP)
    {
        ret = swSocket_udp_sendto(serv_sock, address, port, resp_data, n);
    }
    else if (packet->socket_type == SW_SOCK_UDP6)
    {
        ret = swSocket_udp_sendto6(serv_sock, address, port, resp_data, n);
    }
    else if (packet->socket_type == SW_SOCK_UNIX_DGRAM)
    {
        ret = swSocket_unix_sendto(serv_sock, address, resp_data, n);
    }
    else
    {
        assert(0);
        return 1;
    }

    if (ret < 0)
    {
        swNotice("send to client fail. errno=%d", errno);
    }
    else
    {
        swNotice("send %d bytes to client success. data=%s", n, resp_data);
    }

    return SW_OK;
}

void my_onStart(swServer *serv)
{
    swNotice("Server is running");
}

void my_onShutdown(swServer *serv)
{
    swNotice("Server is shutdown");
}

void my_onConnect(swServer *serv, swDataHead *info)
{
    swNotice("PID=%d\tConnect fd=%d|reactor_id=%d", getpid(), info->fd, info->reactor_id);
}

void my_onClose(swServer *serv, swDataHead *info)
{
    swNotice("PID=%d\tClose fd=%d|reactor_id=%d", getpid(), info->fd, info->reactor_id);
}

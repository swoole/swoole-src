/**
 * cmake .
 * make test_server
 * ./bin/test_server
 */
#include "server.h"

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
    int ret;
    swServer serv;
    swServer_init(&serv);

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

    // swSignal_add(SIGINT, user_signal);

    //create Server
    ret = swServer_create(&serv);
    if (ret < 0)
    {
        swTrace("create server fail[error=%d].\n", ret);
        exit(0);
    }

    swListenPort *port = swServer_add_port(&serv, SW_SOCK_TCP, "127.0.0.1", 9501);
    port->open_eof_check = 0;
    //config
    port->backlog = 128;
    memcpy(port->protocol.package_eof, SW_STRL("\r\n\r\n"));

    swServer_add_port(&serv, SW_SOCK_UDP, "0.0.0.0", 9502);
    swServer_add_port(&serv, SW_SOCK_TCP6, "::", 9503);
    swServer_add_port(&serv, SW_SOCK_UDP6, "::", 9504);

    ret = swServer_start(&serv);
    if (ret < 0)
    {
        swTrace("start server fail[error=%d].\n", ret);
        exit(0);
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
    swConnection *conn = swWorker_get_connection(serv, req_pkg->info.fd);

    swoole_rtrim(req_pkg->data.str, req_pkg->data.length);
    swNotice("onReceive[%d]: ip=%s|port=%d Data=%s|Len=%d", g_receive_count,
        swConnection_get_ip(conn), swConnection_get_port(conn), 
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
    int ret;

    swDgramPacket *packet;

    swWorker_get_data(serv, req, &data);
    packet = (swDgramPacket*) data;

    int serv_sock = req->info.server_fd;

    //udp ipv4
    if (req->info.type == SW_EVENT_UDP)
    {
        inet_ntop(AF_INET, &packet->info.addr.inet_v4.sin_addr, address, sizeof(address));
        port = ntohs(packet->info.addr.inet_v4.sin_port);
    }
    //udp ipv6
    else if (req->info.type == SW_EVENT_UDP6)
    {
        inet_ntop(AF_INET6, &packet->info.addr.inet_v6.sin6_addr, address, sizeof(address));
        port = ntohs(packet->info.addr.inet_v6.sin6_port);
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        strcpy(address, packet->info.addr.un.sun_path);
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

    //udp ipv4
    if (req->info.type == SW_EVENT_UDP)
    {
        ret = swSocket_udp_sendto(serv_sock, address, port, resp_data, n);
    }
    //udp ipv6
    else if (req->info.type == SW_EVENT_UDP6)
    {
        ret = swSocket_udp_sendto6(serv_sock, address, port, resp_data, n);
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        ret = swSocket_unix_sendto(serv_sock, address, resp_data, n);
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
    swNotice("Server is shutdown\n");
}

void my_onConnect(swServer *serv, swDataHead *info)
{
    swNotice("PID=%d\tConnect fd=%d|reactor_id=%d", getpid(), info->fd, info->reactor_id);
}

void my_onClose(swServer *serv, swDataHead *info)
{
    swNotice("PID=%d\tClose fd=%d|reactor_id=%d", getpid(), info->fd, info->reactor_id);
}

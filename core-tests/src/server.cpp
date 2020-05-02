#include "tests.h"

namespace swoole_test
{
static int my_onPacket(swServer *serv, swEventData *req);
static int my_onReceive(swServer *serv, swEventData *req);
static void my_onStart(swServer *serv);
static void my_onShutdown(swServer *serv);
static void my_onConnect(swServer *serv, swDataHead *info);
static void my_onClose(swServer *serv, swDataHead *info);
static void my_onWorkerStart(swServer *serv, int worker_id);
static void my_onWorkerStop(swServer *serv, int worker_id);

static int g_receive_count = 0;

int server_test()
{
    int ret;
    swServer serv;
    swServer_init(&serv);

    serv.reactor_num = 4;
    serv.worker_num = 2;

    serv.factory_mode = SW_MODE_BASE;
    //serv.factory_mode = SW_MODE_SINGLE; //SW_MODE_PROCESS/SW_MODE_THREAD/SW_MODE_BASE/SW_MODE_SINGLE
    serv.max_connection = 10000;
    //serv.open_cpu_affinity = 1;
    //serv.open_tcp_nodelay = 1;
    //serv.daemonize = 1;
//	memcpy(serv.log_file, SW_STRS("/tmp/swoole.log")); //日志

    serv.dispatch_mode = 2;
//	serv.open_tcp_keepalive = 1;

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

//	swSignal_add(SIGINT, user_signal);

    //create Server
    ret = swServer_create(&serv);
    if (ret < 0)
    {
        swTrace("create server fail[error=%d].\n", ret);
        exit(1);
    }

    swListenPort *port = swServer_add_port(&serv, SW_SOCK_TCP, "127.0.0.1", 9501);
    port->open_eof_check = 0;
    //config
    port->backlog = 128;
    memcpy(port->protocol.package_eof, SW_STRL("\r\n\r\n"));  //开启eof检测，启用buffer区

    swServer_add_port(&serv, SW_SOCK_UDP, "0.0.0.0", 9502);
    swServer_add_port(&serv, SW_SOCK_TCP6, "::", 9503);
    swServer_add_port(&serv, SW_SOCK_UDP6, "::", 9504);

    ret = swServer_start(&serv);
    if (ret < 0)
    {
        swTrace("start server fail[error=%d].\n", ret);
        exit(1);
    }
    return 0;
}

void my_onWorkerStart(swServer *serv, int worker_id)
{
    printf("WorkerStart[%d]PID=%d\n", worker_id, getpid());
}

void my_onWorkerStop(swServer *serv, int worker_id)
{
    printf("WorkerStop[%d]PID=%d\n", worker_id, getpid());
}

int my_onReceive(swServer *serv, swEventData *req)
{
    int ret;
    char resp_data[SW_IPC_BUFFER_SIZE];

    g_receive_count++;

    swConnection *conn = swWorker_get_connection(serv, req->info.fd);
    swoole_rtrim(req->data, req->info.len);
    printf("onReceive[%d]: ip=%s|port=%d Data=%s|Len=%d\n", g_receive_count, 
            swSocket_get_ip(conn->socket_type, &conn->info),
            swSocket_get_port(conn->socket_type, &conn->info),
            req->data, req->info.len);

    int n = snprintf(resp_data, SW_IPC_BUFFER_SIZE, "Server: %.*s\n", req->info.len, req->data);
    ret = serv->send(serv, req->info.fd, resp_data, n);
    if (ret < 0)
    {
        printf("send to client fail. errno=%d\n", errno);
    }
    else
    {
        printf("send %d bytes to client success. data=%s\n", n, resp_data);
    }
    return SW_OK;
}

int my_onPacket(swServer *serv, swEventData *req)
{
    int serv_sock = req->info.server_fd;
    char *data;
    serv->get_packet(serv, req, &data);
    swDgramPacket *packet = (swDgramPacket *) data;

    int length;
    char address[256];
    int port = 0;
    int ret;

    if (packet->socket_type == SW_SOCK_UDP)
    {
        inet_ntop(AF_INET6, &packet->socket_addr.addr.inet_v4.sin_addr, address, sizeof(address));
        data = packet->data;
        length = packet->length;
        port = ntohs(packet->socket_addr.addr.inet_v4.sin_port);
    }
    else if (packet->socket_type == SW_SOCK_UDP6)
    {
        inet_ntop(AF_INET6, &packet->socket_addr.addr.inet_v6.sin6_addr, address, sizeof(address));
        data = packet->data;
        length = packet->length;
        port = ntohs(packet->socket_addr.addr.inet_v6.sin6_port);
    }
    else if (packet->socket_type == SW_SOCK_UNIX_DGRAM)
    {
        strcpy(address, packet->socket_addr.addr.un.sun_path);
        data = packet->data;
        length = packet->length;
    }

    printf("Packet[client=%s:%d, %d bytes]: data=%.*s\n", address, port, length, length, data);

    char resp_data[SW_IPC_BUFFER_SIZE];
    int n = snprintf(resp_data, SW_IPC_BUFFER_SIZE, "Server: %.*s", length, data);

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

    if (ret < 0)
    {
        printf("send to client fail. errno=%d\n", errno);
    }
    else
    {
        printf("send %d bytes to client success. data=%s\n", n, resp_data);
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
    printf("PID=%d\tConnect fd=%d|reactor_id=%d\n", getpid(), info->fd, info->reactor_id);
}

void my_onClose(swServer *serv, swDataHead *info)
{
    printf("PID=%d\tClose fd=%d|reactor_id=%d\n", getpid(), info->fd, info->reactor_id);
}

}

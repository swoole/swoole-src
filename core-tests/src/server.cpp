#include "swoole.h"
#include "server.h"

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
        exit(0);
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
        exit(0);
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
    printf("onReceive[%d]: ip=%s|port=%d Data=%s|Len=%d\n", g_receive_count, swConnection_get_ip(conn),
            swConnection_get_port(conn), req->data, req->info.len);

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
    swWorker_get_data(serv, req, &data);
    swDgramPacket *packet = (swDgramPacket *) data;

    int length;
    char address[256];
    int port = 0;
    int ret;

    //udp ipv4
    if (req->info.type == SW_EVENT_UDP)
    {
        inet_ntop(AF_INET6, &packet->info.addr.inet_v4.sin_addr, address, sizeof(address));
        data = packet->data;
        length = packet->length;
        port = ntohs(packet->info.addr.inet_v4.sin_port);
    }
    //udp ipv6
    else if (req->info.type == SW_EVENT_UDP6)
    {
        inet_ntop(AF_INET6, &packet->info.addr.inet_v6.sin6_addr, address, sizeof(address));
        data = packet->data;
        length = packet->length;
        port = ntohs(packet->info.addr.inet_v6.sin6_port);
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        strcpy(address, packet->info.addr.un.sun_path);
        data = packet->data;
        length = packet->length;
    }

    printf("Packet[client=%s:%d, %d bytes]: data=%.*s\n", address, port, length, length, data);

    char resp_data[SW_IPC_BUFFER_SIZE];
    int n = snprintf(resp_data, SW_IPC_BUFFER_SIZE, "Server: %.*s", length, data);

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

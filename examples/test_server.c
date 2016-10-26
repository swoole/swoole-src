/**
 * cmake .
 * make test_server
 * ./bin/test_server
 */
#include "Server.h"

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
    swServer_init(&serv);  //初始化

    serv.reactor_num = 4;  //reactor线程数量
    serv.worker_num = 2;  //worker进程数量

    serv.factory_mode = SW_MODE_BASE;
    //serv.factory_mode = SW_MODE_SINGLE; //SW_MODE_PROCESS/SW_MODE_THREAD/SW_MODE_BASE/SW_MODE_SINGLE
    serv.max_connection = 10000;
    //serv.open_cpu_affinity = 1;
    //serv.open_tcp_nodelay = 1;
    //serv.daemonize = 1;
//	memcpy(serv.log_file, SW_STRL("/tmp/swoole.log")); //日志

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
    memcpy(port->protocol.package_eof, SW_STRL("\r\n\r\n") - 1);  //开启eof检测，启用buffer区

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
    char resp_data[SW_BUFFER_SIZE];

    g_receive_count++;

    swConnection *conn = swWorker_get_connection(serv, req->info.fd);
    swoole_rtrim(req->data, req->info.len);
    printf("onReceive[%d]: ip=%s|port=%d Data=%s|Len=%d\n", g_receive_count, swConnection_get_ip(conn),
            swConnection_get_port(conn), req->data, req->info.len);

    int n = snprintf(resp_data, SW_BUFFER_SIZE, "Server: %*s\n", req->info.len, req->data);
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
    swDgramPacket *packet;

    swString *buffer = swWorker_get_buffer(serv, req->info.from_id);
    packet = (swDgramPacket*) buffer->str;

    int serv_sock = req->info.from_fd;
    char *data;
    int length;
    char address[256];
    int port = 0;
    int ret;

    //udp ipv4
    if (req->info.type == SW_EVENT_UDP)
    {
        struct in_addr sin_addr;
        sin_addr.s_addr = packet->addr.v4.s_addr;
        char *tmp = inet_ntoa(sin_addr);
        memcpy(address, tmp, strlen(tmp));
        data = packet->data;
        length = packet->length;
        port = packet->port;
    }
    //udp ipv6
    else if (req->info.type == SW_EVENT_UDP6)
    {
        inet_ntop(AF_INET6, &packet->addr.v6, address, sizeof(address));
        data = packet->data;
        length = packet->length;
        port = packet->port;
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        memcpy(address, packet->data, packet->addr.un.path_length);
        data = packet->data + packet->addr.un.path_length;
        length = packet->length - packet->addr.un.path_length;
    }

    printf("Packet[client=%s:%d, %d bytes]: data=%*s\n", address, port, length, length, data);

    char resp_data[SW_BUFFER_SIZE];
    int n = snprintf(resp_data, SW_BUFFER_SIZE, "Server: %*s", length, data);

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
        memcpy(address, packet->data, packet->addr.un.path_length);
        data = packet->data + packet->addr.un.path_length;
        length = packet->length - packet->addr.un.path_length;
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
    sw_log("Server is running");
}

void my_onShutdown(swServer *serv)
{
    sw_log("Server is shutdown\n");
}

void my_onConnect(swServer *serv, swDataHead *info)
{
    printf("PID=%d\tConnect fd=%d|from_id=%d\n", getpid(), info->fd, info->from_id);
}

void my_onClose(swServer *serv, swDataHead *info)
{
    printf("PID=%d\tClose fd=%d|from_id=%d\n", getpid(), info->fd, info->from_id);
}

#include <string.h>
#include "swoole.h"
#include "Server.h"
#include "hashtable.h"
#include "RingMempool.h"
#include <netinet/tcp.h>

int swoole_running = 1;
int my_onReceive(swFactory *factory, swEventData *req);
void my_onStart(swServer *serv);
void my_onShutdown(swServer *serv);
void my_onConnect(swServer *serv, int fd,int from_id);
void my_onClose(swServer *serv, int fd,int from_id);
void my_onTimer(swServer *serv, int interval);

void p_str(void *str)
{
	printf("Str: %s|len=%ld\n", (char *)str, strlen((char *)str));
}

int main(int argc, char **argv)
{
	swServer serv;
	int ret;

	//u1_test1();
	//return 0;
	//ds_test1();
	//return 0;

	swServer_init(&serv);
	//strncpy(argv[0], "SwooleServer", 127);

	//config
	serv.backlog = 128;
	serv.poll_thread_num = 4;
	serv.writer_num = 4;
	serv.worker_num = 4;
	serv.factory_mode = 2;
	serv.open_cpu_affinity = 1;
	serv.open_tcp_nodelay = 1;
	//serv.daemonize = 1;

	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 9500);
	swServer_addListen(&serv, SW_SOCK_TCP, "127.0.0.1", 9501);
	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 9502);
	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 8888);

	//swServer_addTimer(&serv, 2);
	//swServer_addTimer(&serv, 10);

	serv.onStart = my_onStart;
	serv.onShutdown = my_onShutdown;
	serv.onConnect = my_onConnect;
	serv.onReceive = my_onReceive;
	serv.onClose = my_onClose;
	serv.onTimer = my_onTimer;
	//create Server
	ret = swServer_create(&serv);
	if (ret < 0)
	{
		swTrace("create server fail[error=%d].\n", ret);
		exit(0);
	}
	ret = swServer_start(&serv);
	if (ret < 0)
	{
		swTrace("start server fail[error=%d].\n", ret);
		exit(0);
	}
	return 0;
}

void my_onTimer(swServer *serv, int interval)
{
	switch(interval)
	{
	case 1:
		printf("Timer[%d]\n", 1);
		break;
	case 10:
		printf("Timer[%d]\n", 10);
		break;
	default:
		break;
	}
}

int my_onReceive(swFactory *factory, swEventData *req)
{
	int ret;
	char resp_data[SW_BUFFER_SIZE];
	swSendData resp;

	resp.fd = req->fd; //fd can be not source fd.
	resp.len = req->len + 8;
	resp.from_id = req->from_id;

	swTrace("Data Len=%d\n", req->len);
	snprintf(resp_data, resp.len, "Server:%s", req->data);
	resp.data = resp_data;
	ret = factory->finish(factory, &resp);
	if(ret < 0)
	{

	}
	swTrace("finish\n");
	return SW_OK;
}

void my_onStart(swServer *serv)
{
	printf("Server is running\n");
}

void my_onShutdown(swServer *serv)
{
	printf("Server is shutdown\n");
}

void my_onConnect(swServer *serv, int fd,int from_id)
{
	printf("Connect fd=%d|from_id=%d\n", fd, from_id);
}

void my_onClose(swServer *serv, int fd,int from_id)
{
	printf("Close fd=%d|from_id=%d\n", fd, from_id);
}

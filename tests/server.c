#include "tests.h"
#include "swoole.h"
#include "Server.h"

int my_onReceive(swFactory *factory, swEventData *req);
void my_onStart(swServer *serv);
void my_onShutdown(swServer *serv);
void my_onConnect(swServer *serv, int fd, int from_id);
void my_onClose(swServer *serv, int fd, int from_id);
void my_onTimer(swServer *serv, int interval);

char* php_rtrim(char *str, int len)
{
	int i;
	for (i = len; i > 0; i--)
	{
		switch(str[i])
		{
		case ' ':
		case '\0':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
			str[i] = 0;
			break;
		default:
			return str;
		}
	}
	return str;
}

swUnitTest(server_test)
{
	swServer serv;
	int ret;

	swServer_init(&serv);
	//strncpy(argv[0], "SwooleServer", 127);

	//config
	serv.backlog = 128;
	serv.reactor_num = 2;
	serv.worker_num = 4;
	serv.factory_mode = 3;

	//serv.open_cpu_affinity = 1;
	//serv.open_tcp_nodelay = 1;
	//serv.daemonize = 1;
	//serv.open_eof_check = 1;

	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 9500);
	swServer_add_listener(&serv, SW_SOCK_TCP, "127.0.0.1", 9501);
	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 9502);
	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 8888);

	//swServer_addTimer(&serv, 2);
	//swServer_addTimer(&serv, 4);

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
	printf("Timer Interval=[%d]\n", interval);
}

static int receive_count = 0;

int my_onReceive(swFactory *factory, swEventData *req)
{
	int ret;
	char resp_data[SW_BUFFER_SIZE];
	swSendData resp;
	receive_count ++;
	resp.info.fd = req->info.fd; //fd can be not source fd.
	resp.info.len = req->info.len + 8;
	resp.info.from_id = req->info.from_id;
	req->data[req->info.len] = 0;

	snprintf(resp_data, resp.info.len, "Server:%s", req->data);
	resp.data = resp_data;
	ret = factory->finish(factory, &resp);
	if (ret < 0)
	{
		printf("send to client fail.errno=%d\n", errno);
	}
	printf("onReceive[%d]: Data=%s|Len=%d\n",receive_count, php_rtrim(req->data, req->info.len), req->info.len);
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

void my_onConnect(swServer *serv, int fd, int from_id)
{
	printf("Connect fd=%d|from_id=%d\n", fd, from_id);
}

void my_onClose(swServer *serv, int fd, int from_id)
{
	printf("Close fd=%d|from_id=%d\n", fd, from_id);
}

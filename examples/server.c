/**
* gcc -o server server.c -lswoole
*/
#include <swoole/Server.h>
#include <swoole/swoole.h>
#include <swoole/Client.h>

int my_onReceive(swFactory *factory, swEventData *req);
void my_onStart(swServer *serv);
void my_onShutdown(swServer *serv);
void my_onConnect(swServer *serv, int fd, int from_id);
void my_onClose(swServer *serv, int fd, int from_id);
void my_onTimer(swServer *serv, int interval);
void my_onWorkerStart(swServer *serv, int worker_id);
void my_onWorkerStop(swServer *serv, int worker_id);

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


int main(int argc, char **argv)
{
	int ret;

	swServer serv;
	swServer_init(&serv); //初始化

	//config
	serv.reactor_num = 2; //reactor线程数量
	serv.worker_num = 4;      //worker进程数量

	serv.factory_mode = SW_MODE_PROCESS; //SW_MODE_PROCESS SW_MODE_THREAD SW_MODE_BASE
	serv.max_connection = 100000;
	//serv.open_cpu_affinity = 1;
	//serv.open_tcp_nodelay = 1;
	//serv.daemonize = 1;
	//serv.open_eof_check = 1;

	//create Server
	ret = swServer_create(&serv);
	if (ret < 0)
	{
		swTrace("create server fail[error=%d].\n", ret);
		exit(0);
	}

	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 9500);
	swListenPort *port = swServer_add_port(&serv, SW_SOCK_TCP, "127.0.0.1", 9501);
	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 9502);
	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 8888);
	port->backlog = 128;

	serv.onStart = my_onStart;
	serv.onShutdown = my_onShutdown;
	serv.onConnect = my_onConnect;
	serv.onReceive = my_onReceive;
	serv.onClose = my_onClose;
	serv.onWorkerStart = my_onWorkerStart;
	serv.onWorkerStop = my_onWorkerStop;

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
	printf("Worker[%d]PID=%d start\n", worker_id, getpid());
}

void my_onWorkerStop(swServer *serv, int worker_id)
{
	printf("Worker[%d]PID=%d stop\n", worker_id, getpid());
}

void my_onTimer(swServer *serv, int interval)
{
	printf("Timer Interval=[%d]\n", interval);
}

static int receive_count = 0;

int my_onReceive(swServer *serv, swEventData *req)
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
	ret = serv->send(serv, &resp);
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
	printf("PID=%d\tConnect fd=%d|from_id=%d\n", getpid(), fd, from_id);
}

void my_onClose(swServer *serv, int fd, int from_id)
{
	printf("PID=%d\tClose fd=%d|from_id=%d\n", getpid(), fd, from_id);
}

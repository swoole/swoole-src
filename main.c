#include <string.h>
#include "swoole.h"
#include "Server.h"

int swoole_running = 1;
int my_onReceive(swFactory *factory, swEventData *req);
void my_onStart(swServer *serv);
void my_onShutdown(swServer *serv);
void my_onConnect(swServer *serv, int fd,int from_id);
void my_onClose(swServer *serv, int fd,int from_id);

int main(int argc, char **argv)
{
	swServer serv;
	int ret;
	swServer_init(&serv);

	//strncpy(argv[0], "SwooleServer", 127);

	//config
	serv.port = 9500;
	serv.host = "127.0.0.1";
	serv.backlog = 128;
	serv.poll_thread_num = 3;
	serv.writer_num = 2;
	serv.worker_num = 4;
	serv.factory_mode = 2;
	//serv.daemonize = 1;

	serv.onStart = my_onStart;
	serv.onShutdown = my_onShutdown;
	serv.onConnect = my_onConnect;
	serv.onReceive = my_onReceive;
	serv.onClose = my_onClose;

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

int my_onReceive(swFactory *factory, swEventData *req)
{
	int ret;
	char resp_data[SW_BUFFER_SIZE];
	swSendData resp;

	resp.fd = req->fd; //fd can be not source fd.
	resp.len = req->len + 8;

	swTrace("Data Len=%d\n", req->len);
	snprintf(resp_data, resp.len, "Server:%s", req->data);
	resp.data = resp_data;
	ret = factory->finish(factory, &resp);
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

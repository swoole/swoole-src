#include "swoole.h"
#include "Server.h"
#include "Client.h"
#include "memory.h"
#include "tests.h"

int my_onReceive(swFactory *factory, swEventData *req);
void my_onStart(swServer *serv);
void my_onShutdown(swServer *serv);
void my_onConnect(swServer *serv, int fd, int from_id);
void my_onClose(swServer *serv, int fd, int from_id);
void my_onTimer(swServer *serv, int interval);

int server_main();
int client_main();
void chan_test();

void p_str(void *str)
{
	printf("Str: %s|len=%ld\n", (char *) str, strlen((char *) str));
}

int client_main()
{
	int ret;
	swClient cli, cli2;
	char buf[128];

	//TCP Test
	ret = swClient_create(&cli, SW_SOCK_TCP, SW_SOCK_SYNC);
	if (ret < 0)
	{
		printf("swClient_create.\n");
		return -1;
	}
	ret = cli.connect(&cli, "127.0.0.1", 9501, 0.5, 0);
	if (ret < 0)
	{
		printf("connect fail.\n");
		return -1;
	}

	ret = cli.send(&cli, SW_STRL("TCP: hello world"));
	if (ret < 0)
	{
		printf("send fail.\n");
		return -1;
	}
	ret = cli.recv(&cli, buf, 128, 0);
	if (ret < 0)
	{
		printf("recv fail.\n");
		return -1;
	}
	cli.close(&cli);
	printf("TCP Test OK. data=%s\n", buf);
	printf("---------------------------------------------------\n");

	//UDP Test
	ret = swClient_create(&cli2, SW_SOCK_UDP, SW_SOCK_SYNC);
	if (ret < 0)
	{
		printf("swClient_create.\n");
		return -1;
	}
	ret = cli2.connect(&cli2, "127.0.0.1", 9500, 0.5, 0);
	if (ret < 0)
	{
		printf("connect fail.\n");
		return -1;
	}
	ret = cli2.send(&cli2, SW_STRL("UDP: hello world"));
	if (ret < 0)
	{
		printf("send fail.\n");
		return -1;
	}
	ret = cli2.recv(&cli2, buf, 128, 0);
	if (ret < 0)
	{
		printf("recv fail.\n");
		return -1;
	}
	cli2.close(&cli2);
	printf("UDP Test OK. data=%s\n", buf);
	printf("---------------------------------------------------\n");

	return 0;
}

int main(int argc, char **argv)
{
	//ds_test2();
	//u1_test2();
	//ds_test1();
	int max_len = 128;
	char info[] = "%s server | client | chantest\n";
	if (argc < 2)
	{
		printf(info, argv[0]);
	}
	else if (strncmp(argv[1], "client", max_len) == 0)
	{
		client_main();
	}
	else if (strncmp(argv[1], "server", max_len) == 0)
	{
		server_main();
	}
	else if (strncmp(argv[1], "chantest", max_len) == 0)
	{
		chan_test();
	}
	else if (strncmp(argv[1], "memtest1", max_len) == 0)
	{
		mem_test1();
	}
	else
	{
		printf(info, argv[0]);
	}
	return 0;
}

void chan_test()
{

	int ret, i;
	//int size = 1024 * 1024 * 8; //8M
	int size = 1024 * 200;
	swChanElem *elem;
	char buf[128];
	//void *mem = malloc(size);

	swShareMemory mm;
	swChan *chan;
	void *mem = swShareMemory_mmap_create(&mm, size, NULL );
	if (mem == NULL )
	{
		printf("malloc memory fail.\n");
		return;
	}
	else
	{
		printf("malloc memory OK.mem_addr=%p\n", mem);
	}

	ret = swChan_create(&chan, mem, size, 64);
	if (ret < 0)
	{
		printf("swChan_create fail.\n");
		return;
	}

	buf[127] = '\0';
	memset(buf, 'c', 127);

	int pid = fork();

	if (pid > 0)
	{
		swBreakPoint();
		for (i = 0; i < 7; i++)
		{
			//n = snprintf(buf, 128, "hello world.i=%d", i);
			ret = swChan_push(chan, buf, 128);
			if (ret < 0)
			{
				printf("swChan_push fail.\n");
				return;
			}
		}
		printf(
				"#swChan_pop---------------------------\nmem_addr\t%p\nelem_num\t%d\
				\nelem_size\t%d\nmem_use_num\t%d\nmem_size\t%d\nelem_tail\t%d\nelem_head\t%d\nmem_current\t%d\n",
				chan->mem, chan->elem_num, chan->elem_size, chan->mem_use_num, chan->mem_size, chan->elem_tail,
				chan->elem_head, chan->mem_cur);
		printf("chan_test OK.\n");
		pause();
	}
	else
	{
		sleep(1);
		swBreakPoint();
		for (i = 0; i < 7; i++)
		{
			elem = swChan_pop(chan);
			if (elem == NULL )
			{
				printf("swChan_pop fail.\n");
			}
			else
			{
				printf("Data=%s\n", (char *) elem->ptr);
			}
		}
		printf(
				"#swChan_pop---------------------------\nmem_addr\t%p\nelem_num\t%d\
				\nelem_size\t%d\nmem_use_num\t%d\nmem_size\t%d\nelem_tail\t%d\nelem_head\t%d\nmem_current\t%d\n",
				chan->mem, chan->elem_num, chan->elem_size, chan->mem_use_num, chan->mem_size, chan->elem_tail,
				chan->elem_head, chan->mem_cur);
		pause();
	}
}

int server_main()
{
	swServer serv;
	int ret;

	swServer_init(&serv);
	//strncpy(argv[0], "SwooleServer", 127);

	//config
	serv.backlog = 128;
	serv.poll_thread_num = 1;
	serv.writer_num = 1;
	serv.worker_num = 1;
	serv.factory_mode = 3;
	//serv.open_cpu_affinity = 1;
	//serv.open_tcp_nodelay = 1;
	//serv.daemonize = 1;

	//swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 9500);
	swServer_addListen(&serv, SW_SOCK_TCP, "127.0.0.1", 9501);
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

int my_onReceive(swFactory *factory, swEventData *req)
{
	int ret;
	char resp_data[SW_BUFFER_SIZE];
	swSendData resp;

	resp.fd = req->fd; //fd can be not source fd.
	resp.len = req->len + 8;
	resp.from_id = req->from_id;

	printf("onReceive: Data=%s|Len=%d\n", req->data, req->len);
	snprintf(resp_data, resp.len, "Server:%s", req->data);
	resp.data = resp_data;
	ret = factory->finish(factory, &resp);
	if (ret < 0)
	{
		swWarn("send to client fail.errno=%d\n", errno);
	}
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

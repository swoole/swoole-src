#include "tests.h"
#include "swoole.h"
#include "Client.h"

swReactor main_reactor;

void dns_callback(void *ptr)
{

}

swUnitTest(client_test)
{
    swReactor_create(&main_reactor, 1024);
    SwooleG.main_reactor = &main_reactor;

    swDNS_request request;

    request.domain = "www.baidu.com";
    request.callback = dns_callback;

    swDNSResolver_request(&request);

    return main_reactor.wait(&main_reactor, NULL);

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

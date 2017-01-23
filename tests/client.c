#include "tests.h"
#include "swoole.h"
#include "Client.h"

static swReactor main_reactor;

void dns_callback(char *domain, swDNSResolver_result *result, void *data)
{
    printf("domain [%s]\n", domain);
    int i;
    for (i = 0; i < result->num; i++)
    {
        printf("ip[%d]: %s\n", i, result->host[i].address);
    }
    printf("private data=%s\n", (char *) data);
}

swUnitTest(dnslookup_test)
{
    swReactor_create(&main_reactor, 1024);
    SwooleG.main_reactor = &main_reactor;
    swDNSResolver_request("www.baidu.com", dns_callback, "hello");
    return main_reactor.wait(&main_reactor, NULL);
}

swUnitTest(client_test)
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

	ret = cli.send(&cli, SW_STRL("TCP: hello world"), 0);
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
	ret = cli2.send(&cli2, SW_STRL("UDP: hello world"), 0);
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

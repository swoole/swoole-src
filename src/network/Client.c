#include "swoole.h"
#include "Client.h"

int swClient_create(swClient *cli, int type)
{
	int _domain;
	int _type;

	switch (type)
	{
	case SW_CLIENT_TCP:
		_domain = AF_INET;
		_type = SOCK_STREAM;
		break;
	case SW_CLIENT_TCP6:
		_domain = AF_INET6;
		_type = SOCK_STREAM;
		break;
	case SW_CLIENT_UDP:
		_domain = AF_INET;
		_type = SOCK_DGRAM;
		break;
	case SW_CLIENT_UDP6:
		_domain = AF_INET6;
		_type = SOCK_DGRAM;
		break;
	default:
		return SW_ERR;
	}
	cli->sock = socket(_domain, _type, 0);
	if(cli->sock <0)
	{
		return SW_ERR;
	}
	return cli->sock;
}

int swClient_connect(swClient *cli, char *host, int port, float timeout)
{
	return 0;
}

int swClient_send(swClient *cli, char *data, int len)
{
	return 0;
}

int swClient_recv(swClient *cli, char *data, int len)
{
	return 0;
}


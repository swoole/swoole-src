#include "swoole.h"

int swClientCreate(swNetClient *cli, int type)
{
	return 0;
}

int swClientConnect(swNetClient *cli, char *host, int port, float timeout)
{
	return 0;
}

int swClientSend(swNetClient *cli, char *data, int len)
{
	return 0;
}

int swClientRecv(swNetClient *cli, char *data, int len)
{
	return 0;
}

int swClientOnRecv(swNetClient *cli, char *data, int len, swCallback callback)
{
	return 0;
}

int swClientClose(swNetClient *cli)
{
	return 0;
}

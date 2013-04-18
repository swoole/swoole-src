#include "swoole.h"

void u1_test1()
{
	swPipe p;
	int ret;
	char data[256];

	ret = swPipeBase_create(&p, 1);
	if (ret < 0)
	{
		swTrace("create fail\n");
		return;
	}
	ret = p.write(&p, SW_STRL("hello world") - 1);
	if (ret < 0)
	{
		swTrace("write fail\n");
	}
	ret = p.write(&p, SW_STRL("你好中国。") - 1);
	if (ret < 0)
	{
		swTrace("write fail\n");
	}

	bzero(data, 256);
	ret = p.read(&p, data, 256);
	if (ret < 0)
	{
		swTrace("write fail\n");
	}
	else
	{
		printf("Data = %s\n", data);
	}

}

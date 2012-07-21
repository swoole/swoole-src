#include "swoole.h"

int swFactory_create(swFactory *factory)
{
	factory->dispatch = swFactory_dispatch;
	factory->finish = swFactory_finish;
	factory->start = swFactory_start;
	factory->shutdown = swFactory_shutdown;
	return SW_OK;
}
int swFactory_start(swFactory *factory)
{
	return SW_OK;
}

int swFactory_shutdown(swFactory *factory)
{
	return SW_OK;
}

int swFactory_dispatch(swFactory *factory, swEventData *req)
{
	int ret;
	swTrace("New Task:%s\n",req->data);
	ret= factory->onTask(factory, req);
	return ret;
}

int swFactory_finish(swFactory *factory, swSendData *resp)
{
	return factory->onFinish(factory, resp);
}

int swFactory_check_callback(swFactory *factory)
{
	int step = 0;
	if (factory->onTask == NULL)
	{
		return --step;
	}
	if (factory->onFinish == NULL)
	{
		return --step;
	}
	return SW_OK;
}

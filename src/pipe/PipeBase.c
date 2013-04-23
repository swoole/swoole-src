#include "swoole.h"

int swPipeBase_read(swPipe *p, void *data, int length);
int swPipeBase_write(swPipe *p, void *data, int length);
int swPipeBase_getFd(swPipe *p, int isWriteFd);
void swPipeBase_close(swPipe *p);

typedef struct _swPipeBase
{
	int pipes[2];
} swPipeBase;

int swPipeBase_create(swPipe *p, int blocking)
{
	int ret;
	swPipeBase *object = sw_malloc(sizeof(swPipeBase));
	if (object == NULL)
	{
		return -1;
	}
	p->blocking = blocking;
	ret = pipe(object->pipes);
	if (ret < 0)
	{
		return -1;
	}
	else
	{
		//Nonblock
		if(blocking == 0)
		{
			swSetNonBlock(object->pipes[0]);
			swSetNonBlock(object->pipes[1]);
		}
		p->object = object;
		p->read = swPipeBase_read;
		p->write = swPipeBase_write;
		p->getFd = swPipeBase_getFd;
		p->close = swPipeBase_close;
	}
	return 0;
}

int swPipeBase_read(swPipe *p, void *data, int length)
{
	swPipeBase *this = p->object;
	return read(this->pipes[0], data, length);
}

int swPipeBase_write(swPipe *p, void *data, int length)
{
	swPipeBase *this = p->object;
	return write(this->pipes[1], data, length);
}

int swPipeBase_getFd(swPipe *p, int isWriteFd)
{
	swPipeBase *this = p->object;
	return (isWriteFd == 0) ?  this->pipes[0] : this->pipes[1];
}


void swPipeBase_close(swPipe *p)
{
	swPipeBase *this = p->object;
	close(this->pipes[0]);
	close(this->pipes[1]);
}

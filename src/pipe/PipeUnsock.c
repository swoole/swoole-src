#include "swoole.h"
#include <sys/ipc.h>
#include <sys/msg.h>

int swPipeUnsock_read(swPipe *p, void *data, int length);
int swPipeUnsock_write(swPipe *p, void *data, int length);
int swPipeUnsock_getFd(swPipe *p, int isWriteFd);
void swPipeUnsock_close(swPipe *p);

typedef struct _swPipeUnsock
{
	int socks[2];
} swPipeUnsock;

typedef struct _swPipeUnsock_buf
{
	long int mtype; /* type of received/sent message */
	char mtext[65535]; /* text of the message */
} swPipeUnsock_buf;

int swPipeUnsock_getFd(swPipe *p, int isWriteFd)
{
	swPipeUnsock *this = p->object;
	return isWriteFd == 1 ? this->socks[1] : this->socks[0];
}

void swPipeUnsock_close(swPipe *p)
{
	swPipeUnsock *this = p->object;
	close(this->socks[0]);
	close(this->socks[1]);
	sw_free(this);
}

int swPipeUnsock_create(swPipe *p, int blocking, int protocol)
{
	int ret;
	swPipeUnsock *object = sw_malloc(sizeof(swPipeUnsock));
	if (object == NULL)
	{
		return -1;
	}
	p->blocking = blocking;
	ret = socketpair(PF_LOCAL, protocol, 0, object->socks);
	if (ret < 0)
	{
		return -1;
	}
	else
	{
		//Nonblock
		if (blocking == 0)
		{
			swSetNonBlock(object->socks[0]);
			swSetNonBlock(object->socks[1]);
		}
		p->object = object;
		p->read = swPipeUnsock_read;
		p->write = swPipeUnsock_write;
		p->getFd = swPipeUnsock_getFd;
		p->close = swPipeUnsock_close;
	}
	return 0;
}

int swPipeUnsock_read(swPipe *p, void *data, int length)
{
	return read(((swPipeUnsock *) p->object)->socks[0], data, length);
}

int swPipeUnsock_write(swPipe *p, void *data, int length)
{
	return write(((swPipeUnsock *) p->object)->socks[1], data, length);
}


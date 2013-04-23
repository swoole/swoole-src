#include "swoole.h"
#include <sys/ipc.h>
#include <sys/msg.h>

int swPipeMsg_read(swPipe *p, void *data, int length);
int swPipeMsg_write(swPipe *p, void *data, int length);
int swPipeMsg_getFd(swPipe *p, int isWriteFd);
void swPipeMsg_close(swPipe *p);

typedef struct _swPipeMsg
{
	int msg_id;
	int ipc_wait;
	long type;
} swPipeMsg;

typedef struct _swPipeMsg_buf
{
	long int mtype;		/* type of received/sent message */
	char mtext[65535];		/* text of the message */
} swPipeMsg_buf;

int swPipeMsg_getFd(swPipe *p, int isWriteFd)
{
	return 0;
}

void swPipeMsg_close(swPipe *p)
{
	swPipeMsg *this = p->object;
	msgctl(this->msg_id, IPC_RMID, 0);
	sw_free(this);
}

int swPipeMsg_create(swPipe *p, int blocking, int msg_key, long type)
{
	int msg_id;
	swPipeMsg *object = sw_malloc(sizeof(swPipeMsg));
	if (object == NULL)
	{
		return -1;
	}
	if (blocking == 0)
	{
		object->ipc_wait = IPC_NOWAIT;
	}
	else
	{
		object->ipc_wait = 0;
	}
	p->blocking = blocking;
	msg_id = msgget(msg_key, IPC_CREAT | 0666);
	if (msg_id < 0)
	{
		return -1;
	}
	else
	{
		object->msg_id = msg_id;
		object->type = type;
		p->object = object;
		p->read = swPipeMsg_read;
		p->write = swPipeMsg_write;
		p->getFd = swPipeMsg_getFd;
		p->close = swPipeMsg_close;
	}
	return 0;
}

int swPipeMsg_read(swPipe *p, void *data, int length)
{
	int ret;
	swPipeMsg *this = p->object;
	swPipeMsg_buf msg_buf;

	int flag = this->ipc_wait;
	long type = this->type;

	while (1)
	{
		ret = msgrcv(this->msg_id, &msg_buf, length, type, flag);
		if (ret < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				return -1;
			}
		}
		else
		{
			memcpy(data, msg_buf.mtext, length);
			return ret;
		}
	}
	return 0;
}

int swPipeMsg_write(swPipe *p, void *data, int length)
{
	int ret;
	swPipeMsg_buf msg_buf;
	swPipeMsg *this = p->object;
	msg_buf.mtype = this->type;
	memcpy(msg_buf.mtext, data, length);

	int flag = this->ipc_wait;

	while (1)
	{
		ret = msgsnd(this->msg_id, &msg_buf, length, flag);
		if (ret < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else if(errno == EAGAIN)
			{
				swYield();
				continue;
			}
			else
			{
				return -1;
			}
		}
		else
		{
			return ret;
		}
	}
	return 0;
}

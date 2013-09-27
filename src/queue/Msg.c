#include "swoole.h"
#include <sys/ipc.h>
#include <sys/msg.h>

int swQueueMsg_in(swQueue *p, swQueue_data *in, int data_length);
int swQueueMsg_out(swQueue *p, swQueue_data *out, int buffer_length);
void swQueueMsg_free(swQueue *p);

typedef struct _swQueueMsg
{
	int msg_id;
	int ipc_wait;
	long type;
} swQueueMsg;

void swQueueMsg_free(swQueue *p)
{
	swQueueMsg *object = p->object;
	msgctl(object->msg_id, IPC_RMID, 0);
	sw_free(object);
}

int swQueueMsg_create(swQueue *p, int wait, int msg_key, long type)
{
	int msg_id;
	swQueueMsg *object = sw_malloc(sizeof(swQueueMsg));
	if (object == NULL)
	{
		return -1;
	}
	if (wait == 0)
	{
		object->ipc_wait = IPC_NOWAIT;
	}
	else
	{
		object->ipc_wait = 0;
	}
	p->wait = wait;
	msg_id = msgget(msg_key, IPC_CREAT | IPC_PRIVATE | 0666);
	if (msg_id <= 0)
	{
		return SW_ERR;
	}
	else
	{
		object->msg_id = msg_id;
		object->type = type;
		p->object = object;
		p->in = swQueueMsg_in;
		p->out = swQueueMsg_out;
		p->free = swQueueMsg_free;
	}
	return 0;
}

int swQueueMsg_out(swQueue *p, swQueue_data *data, int length)
{
	int ret;
	swQueueMsg *object = p->object;

	int flag = object->ipc_wait;
	long type = data->mtype;

	while (1)
	{
		ret = msgrcv(object->msg_id, data, length, type, flag);
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
			return ret;
		}
	}
	return 0;
}

int swQueueMsg_in(swQueue *p, swQueue_data *in, int length)
{
	int ret;
	swQueueMsg *object = p->object;

	while (1)
	{
		//send一定不可以阻塞
		ret = msgsnd(object->msg_id, in, length, IPC_NOWAIT);
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

/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

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

int swQueueMsg_create(swQueue *p, int blocking, int msg_key, long type)
{
	int msg_id;
	swQueueMsg *object = sw_malloc(sizeof(swQueueMsg));
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
	msg_id = msgget(msg_key, IPC_CREAT | O_EXCL | 0666);
	if (msg_id < 0)
	{
		swWarn("msgget() failed. Error: %s[%d]", strerror(errno), errno);
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
	swQueueMsg *object = p->object;

	int flag = object->ipc_wait;
	long type = data->mtype;

	return msgrcv(object->msg_id, data, length, type, flag);
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

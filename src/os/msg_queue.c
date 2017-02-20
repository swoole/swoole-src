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
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

void swMsgQueue_free(swMsgQueue *q)
{
    if (q->remove)
    {
        msgctl(q->msg_id, IPC_RMID, 0);
    }
}

void swMsgQueue_set_blocking(swMsgQueue *q, uint8_t blocking)
{
    if (blocking == 0)
    {
        q->flags = q->flags | IPC_NOWAIT;
    }
    else
    {
        q->flags = q->flags & (~IPC_NOWAIT);
    }
}

int swMsgQueue_create(swMsgQueue *q, int blocking, key_t msg_key, long type)
{
    int msg_id;
    msg_id = msgget(msg_key, IPC_CREAT | 0666);
    if (msg_id < 0)
    {
        swSysError("msgget() failed.");
        return SW_ERR;
    }
    else
    {
        bzero(q, sizeof(swMsgQueue));
        q->msg_id = msg_id;
        q->type = type;
        q->blocking = blocking;
        swMsgQueue_set_blocking(q, blocking);
    }
    return 0;
}

int swMsgQueue_pop(swMsgQueue *q, swQueue_data *data, int length)
{
    int ret = msgrcv(q->msg_id, data, length, data->mtype, q->flags);
    if (ret < 0)
    {
        SwooleG.error = errno;
        if (errno != ENOMSG && errno != EINTR)
        {
            swSysError("msgrcv(%d, %d, %ld) failed.", q->msg_id, length, data->mtype);
        }
    }
    return ret;
}

int swMsgQueue_push(swMsgQueue *q, swQueue_data *in, int length)
{
    int ret;

    while (1)
    {
        ret = msgsnd(q->msg_id, in, length, q->flags);
        if (ret < 0)
        {
            SwooleG.error = errno;
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN)
            {
                return -1;
            }
            else
            {
                swSysError("msgsnd(%d, %d, %ld) failed.", q->msg_id, length, in->mtype);
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

int swMsgQueue_stat(swMsgQueue *q, int *queue_num, int *queue_bytes)
{
    struct msqid_ds __stat;
    if (msgctl(q->msg_id, IPC_STAT, &__stat) == 0)
    {
        *queue_num = __stat.msg_qnum;
        *queue_bytes = __stat.msg_cbytes;
        return 0;
    }
    else
    {
        return -1;
    }
}

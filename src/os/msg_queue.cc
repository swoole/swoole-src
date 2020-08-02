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

#include "msg_queue.h"
#include "swoole_log.h"

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

int swMsgQueue_free(swMsgQueue *q) {
    if (msgctl(q->msg_id, IPC_RMID, 0) < 0) {
        swSysWarn("msgctl(%d, IPC_RMID) failed", q->msg_id);
        return SW_ERR;
    }
    return SW_OK;
}

void swMsgQueue_set_blocking(swMsgQueue *q, uint8_t blocking) {
    if (blocking == 0) {
        q->flags = q->flags | IPC_NOWAIT;
    } else {
        q->flags = q->flags & (~IPC_NOWAIT);
    }
}

int swMsgQueue_create(swMsgQueue *q, int blocking, key_t msg_key, int perms) {
    if (perms <= 0 || perms >= 01000) {
        perms = 0666;
    }
    int msg_id;
    msg_id = msgget(msg_key, IPC_CREAT | perms);
    if (msg_id < 0) {
        swSysWarn("msgget() failed");
        return SW_ERR;
    } else {
        sw_memset_zero(q, sizeof(swMsgQueue));
        q->msg_id = msg_id;
        q->perms = perms;
        q->blocking = blocking;
        swMsgQueue_set_blocking(q, blocking);
    }
    return 0;
}

ssize_t swMsgQueue_pop(swMsgQueue *q, swQueue_data *data, size_t length) {
    ssize_t ret = msgrcv(q->msg_id, data, length, data->mtype, q->flags);
    if (ret < 0) {
        swoole_set_last_error(errno);
        if (errno != ENOMSG && errno != EINTR) {
            swSysWarn("msgrcv(%d, %d, %ld) failed", q->msg_id, length, data->mtype);
        }
    }
    return ret;
}

ssize_t swMsgQueue_push(swMsgQueue *q, swQueue_data *in, size_t length) {
    int ret;

    while (1) {
        ret = msgsnd(q->msg_id, in, length, q->flags);
        if (ret < 0) {
            swoole_set_last_error(errno);
            if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN) {
                return -1;
            } else {
                swSysWarn("msgsnd(%d, %d, %ld) failed", q->msg_id, length, in->mtype);
                return -1;
            }
        } else {
            return ret;
        }
    }
    return 0;
}

int swMsgQueue_stat(swMsgQueue *q, size_t *queue_num, size_t *queue_bytes) {
    struct msqid_ds __stat;
    if (msgctl(q->msg_id, IPC_STAT, &__stat) == 0) {
        *queue_num = __stat.msg_qnum;
        *queue_bytes = __stat.msg_cbytes;
        return 0;
    } else {
        return -1;
    }
}

int swMsgQueue_set_capacity(swMsgQueue *q, size_t queue_bytes) {
    struct msqid_ds __stat;
    if (msgctl(q->msg_id, IPC_STAT, &__stat) != 0) {
        return -1;
    }
    __stat.msg_qbytes = queue_bytes;
    if (msgctl(q->msg_id, IPC_SET, &__stat)) {
        swSysWarn("msgctl(msqid=%d, IPC_SET, msg_qbytes=%d) failed", q->msg_id, queue_bytes);
        return -1;
    }
    return 0;
}

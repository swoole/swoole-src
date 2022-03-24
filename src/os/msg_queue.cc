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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "swoole_msg_queue.h"

#include <sys/ipc.h>
#include <sys/msg.h>

namespace swoole {

bool MsgQueue::destroy() {
    if (msgctl(msg_id_, IPC_RMID, 0) < 0) {
        swoole_sys_warning("msgctl(%d, IPC_RMID) failed", msg_id_);
        return false;
    }
    msg_id_ = -1;
    return true;
}

void MsgQueue::set_blocking(bool blocking) {
    if (blocking == 0) {
        flags_ = flags_ | IPC_NOWAIT;
    } else {
        flags_ = flags_ & (~IPC_NOWAIT);
    }
}

MsgQueue::MsgQueue(key_t msg_key, bool blocking, int perms) {
    if (perms <= 0 || perms >= 01000) {
        perms = 0666;
    }
    msg_key_ = msg_key;
    flags_ = 0;
    perms_ = perms;
    blocking_ = blocking;
    msg_id_ = msgget(msg_key, IPC_CREAT | perms);
    if (msg_id_ < 0) {
        swoole_sys_warning("msgget() failed");
    } else {
        set_blocking(blocking);
    }
}

MsgQueue::~MsgQueue() {
    // private queue must be destroyed
    if (msg_key_ == IPC_PRIVATE && msg_id_ >= 0) {
        destroy();
    }
}

ssize_t MsgQueue::pop(QueueNode *data, size_t mdata_size) {
    ssize_t ret = msgrcv(msg_id_, data, mdata_size, data->mtype, flags_);
    if (ret < 0) {
        swoole_set_last_error(errno);
        if (errno != ENOMSG && errno != EINTR) {
            swoole_sys_warning("msgrcv(%d, %zu, %ld) failed", msg_id_, mdata_size, data->mtype);
        }
    }
    return ret;
}

bool MsgQueue::push(QueueNode *in, size_t mdata_length) {
    while (1) {
        if (msgsnd(msg_id_, in, mdata_length, flags_) == 0) {
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EAGAIN) {
            swoole_sys_warning("msgsnd(%d, %lu, %ld) failed", msg_id_, mdata_length, in->mtype);
        }
        swoole_set_last_error(errno);
        break;

    }
    return false;
}

bool MsgQueue::stat(size_t *queue_num, size_t *queue_bytes) {
    struct msqid_ds __stat;
    if (msgctl(msg_id_, IPC_STAT, &__stat) == 0) {
        *queue_num = __stat.msg_qnum;
#ifndef __NetBSD__
        *queue_bytes = __stat.msg_cbytes;
#else
        *queue_bytes = __stat._msg_cbytes;
#endif
        return true;
    } else {
        return false;
    }
}

bool MsgQueue::set_capacity(size_t queue_bytes) {
    struct msqid_ds __stat;
    if (msgctl(msg_id_, IPC_STAT, &__stat) != 0) {
        return false;
    }
    __stat.msg_qbytes = queue_bytes;
    if (msgctl(msg_id_, IPC_SET, &__stat)) {
        swoole_sys_warning("msgctl(msqid=%d, IPC_SET, msg_qbytes=%lu) failed", msg_id_, queue_bytes);
        return false;
    }
    return true;
}
}  // namespace swoole

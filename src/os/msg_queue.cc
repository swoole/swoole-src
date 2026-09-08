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

#include "swoole_msg_queue.h"

namespace swoole {
#ifdef HAVE_MSGQUEUE
#include <sys/ipc.h>
#include <sys/msg.h>

bool MsgQueue::destroy() {
    if (msgctl(msg_id_, IPC_RMID, nullptr) < 0) {
        swoole_sys_warning("msgctl(%d, IPC_RMID) failed", msg_id_);
        return false;
    }
    msg_id_ = -1;
    return true;
}

void MsgQueue::set_blocking(const bool blocking) {
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
        swoole_sys_warning("msgget(key=%ld, uid=%d) failed", (long) msg_key, (int) geteuid());
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

bool MsgQueue::set_access(uid_t uid, gid_t gid, mode_t mode) {
    msqid_ds status;
    if (msgctl(msg_id_, IPC_STAT, &status) < 0) {
        swoole_sys_warning("msgctl(%d, IPC_STAT) failed", msg_id_);
        return false;
    }

    bool root = geteuid() == 0;
    bool trusted_uid = status.msg_perm.uid == uid || (root && status.msg_perm.uid == 0);
    // The creator keeps owner-class access even after ownership changes.
    bool trusted_cuid = status.msg_perm.cuid == uid || (root && status.msg_perm.cuid == 0);
    bool replace = !trusted_uid || !trusted_cuid || (status.msg_perm.mode & 0022);
    size_t pending = 0;

    if (replace) {
        if (msg_key_ == IPC_PRIVATE) {
            // Server initialization cannot reach this, but replacing a private queue would silently orphan it.
            swoole_warning("cannot replace a private message queue");
            return false;
        }

        pending = status.msg_qnum;
        if (msgctl(msg_id_, IPC_RMID, nullptr) < 0) {
            swoole_sys_warning("msgctl(%d, IPC_RMID) failed", msg_id_);
            return false;
        }
        msg_id_ = msgget(msg_key_, IPC_CREAT | IPC_EXCL | (mode & 0777));
        if (msg_id_ < 0) {
            swoole_sys_warning("msgget(key=%ld) failed", (long) msg_key_);
            return false;
        }
        if (msgctl(msg_id_, IPC_STAT, &status) < 0) {
            swoole_sys_warning("msgctl(%d, IPC_STAT) failed", msg_id_);
            destroy();
            return false;
        }
    }

    status.msg_perm.uid = uid;
    status.msg_perm.gid = gid;
    status.msg_perm.mode = (status.msg_perm.mode & ~0777) | (mode & 0777);
    if (msgctl(msg_id_, IPC_SET, &status) < 0) {
        swoole_sys_warning("msgctl(%d, IPC_SET) failed", msg_id_);
        if (replace) {
            destroy();
        }
        return false;
    }
    if (replace) {
        swoole_warning("message queue[key=%ld] was replaced; discarded %zu pending message%s",
                       (long) msg_key_,
                       pending,
                       pending == 1 ? "" : "s");
    }
    return true;
}

ssize_t MsgQueue::pop(QueueNode *data, size_t mdata_size) const {
    ssize_t ret = msgrcv(msg_id_, data, mdata_size, data->mtype, flags_);
    if (ret < 0) {
        swoole_set_last_error(errno);
        if (errno != ENOMSG && errno != EINTR) {
            swoole_sys_warning("msgrcv(%d, %zu, %ld) failed", msg_id_, mdata_size, data->mtype);
        }
    }
    return ret;
}

bool MsgQueue::push(const QueueNode *in, size_t mdata_length) const {
    while (true) {
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

bool MsgQueue::stat(size_t *queue_num, size_t *queue_bytes) const {
    msqid_ds _stat;
    if (msgctl(msg_id_, IPC_STAT, &_stat) == 0) {
        *queue_num = _stat.msg_qnum;
#ifndef __NetBSD__
        *queue_bytes = _stat.msg_cbytes;
#else
        *queue_bytes = __stat._msg_cbytes;
#endif
        return true;
    }
    return false;
}

bool MsgQueue::set_capacity(size_t queue_bytes) const {
    msqid_ds _stat;
    if (msgctl(msg_id_, IPC_STAT, &_stat) != 0) {
        return false;
    }
    _stat.msg_qbytes = queue_bytes;
    if (msgctl(msg_id_, IPC_SET, &_stat)) {
        swoole_sys_warning("msgctl(msqid=%d, IPC_SET, msg_qbytes=%lu) failed", msg_id_, queue_bytes);
        return false;
    }
    return true;
}
#else
MsgQueue::MsgQueue(key_t msg_key, bool blocking, int perms) {
    swoole_error("current platform does not support `sysvmsg`");
}

void MsgQueue::set_blocking(bool blocking) {}

bool MsgQueue::set_access(uid_t uid, gid_t gid, mode_t mode) {
    return false;
}

bool MsgQueue::set_capacity(size_t queue_bytes) const {
    return false;
}

bool MsgQueue::push(const QueueNode *in, size_t mdata_length) const {
    return false;
}

ssize_t MsgQueue::pop(QueueNode *out, size_t mdata_size) const {
    return -1;
}

bool MsgQueue::stat(size_t *queue_num, size_t *queue_bytes) const {
    return false;
}

bool MsgQueue::destroy() {
    return false;
}

MsgQueue::~MsgQueue() {
}
#endif
}  // namespace swoole

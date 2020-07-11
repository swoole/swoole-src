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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"

struct swQueue_data {
    long mtype;                      /* type of received/sent message */
    char mdata[sizeof(swEventData)]; /* text of the message */
};

struct swMsgQueue {
    int blocking;
    int msg_id;
    int flags;
    int perms;
};

int swMsgQueue_create(swMsgQueue *q, int blocking, key_t msg_key, int perms);
void swMsgQueue_set_blocking(swMsgQueue *q, uint8_t blocking);
int swMsgQueue_set_capacity(swMsgQueue *q, int queue_bytes);
int swMsgQueue_push(swMsgQueue *q, swQueue_data *in, int data_length);
int swMsgQueue_pop(swMsgQueue *q, swQueue_data *out, int buffer_length);
int swMsgQueue_stat(swMsgQueue *q, int *queue_num, int *queue_bytes);
int swMsgQueue_free(swMsgQueue *q);

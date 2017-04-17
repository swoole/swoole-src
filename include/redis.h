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

#ifndef SW_REDIS_H_
#define SW_REDIS_H_

#ifdef __cplusplus
extern "C"
{
#endif

enum swRedis_receive_state
{
    SW_REDIS_RECEIVE_TOTAL_LINE,
    SW_REDIS_RECEIVE_LENGTH,
    SW_REDIS_RECEIVE_STRING,
};

enum swRedis_reply_type
{
    SW_REDIS_REPLY_ERROR,
    SW_REDIS_REPLY_NIL,
    SW_REDIS_REPLY_STATUS,
    SW_REDIS_REPLY_INT,
    SW_REDIS_REPLY_STRING,
    SW_REDIS_REPLY_SET,
    SW_REDIS_REPLY_MAP,
};

#define SW_REDIS_RETURN_NIL                 "$-1\r\n"

#define SW_REDIS_MAX_COMMAND_SIZE           64
#define SW_REDIS_MAX_LINES                  128
#define SW_REDIS_MAX_STRING_SIZE            536870912  //512M

static sw_inline char* swRedis_get_number(char *p, int *_ret)
{
    char *endptr;
    p++;
    int ret = strtol(p, &endptr, 10);
    if (strncmp(SW_CRLF, endptr, SW_CRLF_LEN) == 0)
    {
        p += (endptr - p) + SW_CRLF_LEN;
        *_ret = ret;
        return p;
    }
    else
    {
        return NULL;
    }
}

int swRedis_recv(swProtocol *protocol, swConnection *conn, swString *buffer);

#ifdef __cplusplus
}
#endif

#endif /* SW_REDIS_H_ */

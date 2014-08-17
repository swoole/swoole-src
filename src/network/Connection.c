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
#include "Server.h"
#include "Connection.h"

#include <sys/stat.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL        0
#endif

int swConnection_send_blocking(int fd, void *data, int length, int timeout)
{
    int n, writen = length;

    while (writen > 0)
    {
        if (swSocket_wait(fd, timeout, SW_EVENT_WRITE) < 0)
        {
            return SW_ERR;
        }
        else
        {
            n = send(fd, data, writen, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (n < 0)
            {
                swWarn("send() failed. Error: %s[%d]", strerror(errno), errno);
                return SW_ERR;
            }
            else
            {
                writen -= n;
                continue;
            }
        }
    }
    return 0;
}

/**
 * send buffer to client
 */
int swConnection_buffer_send(swConnection *conn)
{
    int ret, sendn;

    swBuffer *buffer = conn->out_buffer;
    swBuffer_trunk *trunk = swBuffer_get_trunk(buffer);
    sendn = trunk->length - trunk->offset;

    if (sendn == 0)
    {
        swBuffer_pop_trunk(buffer, trunk);
        return SW_CONTINUE;
    }
    ret = swConnection_send(conn, trunk->store.ptr + trunk->offset, sendn, 0);
    //printf("BufferOut: reactor=%d|sendn=%d|ret=%d|trunk->offset=%d|trunk_len=%d\n", reactor->id, sendn, ret, trunk->offset, trunk->length);
    if (ret < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swWarn("send to fd[%d] failed. Error: %s[%d]", conn->fd, strerror(errno), errno);
            return SW_OK;
        case SW_CLOSE:
            return SW_CLOSE;
        case SW_WAIT:
            return SW_WAIT;
        default:
            return SW_CONTINUE;
        }
    }
    //trunk full send
    else if (ret == sendn || sendn == 0)
    {
        swBuffer_pop_trunk(buffer, trunk);
    }
    else
    {
        trunk->offset += ret;
    }
    return SW_CONTINUE;
}

swString* swConnection_get_string_buffer(swConnection *conn)
{
    swString *buffer = conn->object;
    if (buffer == NULL)
    {
        return swString_new(SW_BUFFER_SIZE);
    }
    else
    {
        return buffer;
    }
}

int swConnection_sendfile(swConnection *conn, char *filename)
{
    if (conn->out_buffer == NULL)
    {
        conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
        if (conn->out_buffer == NULL)
        {
            return SW_ERR;
        }
    }

    swBuffer_trunk *trunk = swBuffer_new_trunk(conn->out_buffer, SW_TRUNK_SENDFILE, 0);
    if (trunk == NULL)
    {
        swWarn("get out_buffer trunk failed.");
        return SW_ERR;
    }
    swTask_sendfile *task = sw_malloc(sizeof(swTask_sendfile));
    if (task == NULL)
    {
        swWarn("malloc for swTask_sendfile failed.");
        //TODO: 回收这里的内存
        return SW_ERR;
    }
    bzero(task, sizeof(swTask_sendfile));

    task->filename = strdup(filename);
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        swWarn("open file[%s] failed. Error: %s[%d]", task->filename, strerror(errno), errno);
        return SW_ERR;
    }
    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0)
    {
        swWarn("swoole_async_readfile: fstat failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    task->filesize = file_stat.st_size;
    task->fd = file_fd;
    trunk->store.ptr = (void *)task;

    return SW_OK;
}


void swConnection_clear_string_buffer(swConnection *conn)
{
    swString *buffer = conn->object;
    if (buffer != NULL)
    {
        swString_free(buffer);
        conn->object = NULL;
    }
}

volatile swBuffer_trunk* swConnection_get_in_buffer(swConnection *conn)
{
    volatile swBuffer_trunk *trunk = NULL;
    swBuffer *buffer;

    if (conn->in_buffer == NULL)
    {
        buffer = swBuffer_new(SW_BUFFER_SIZE);
        //buffer create failed
        if (buffer == NULL)
        {
            return NULL;
        }
        //new trunk
        trunk = swBuffer_new_trunk(buffer, SW_TRUNK_DATA, buffer->trunk_size);
        if (trunk == NULL)
        {
            sw_free(buffer);
            return NULL;
        }
        conn->in_buffer = buffer;
    }
    else
    {
        buffer = conn->in_buffer;
        trunk = buffer->tail;
        if (trunk == NULL || trunk->length == buffer->trunk_size)
        {
            trunk = swBuffer_new_trunk(buffer, SW_TRUNK_DATA, buffer->trunk_size);
        }
    }
    return trunk;
}

volatile swBuffer_trunk* swConnection_get_out_buffer(swConnection *conn, uint32_t type)
{
    volatile swBuffer_trunk *trunk;
    if (conn->out_buffer == NULL)
    {
        conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
        if (conn->out_buffer == NULL)
        {
            return NULL;
        }
    }
    if (type == SW_TRUNK_SENDFILE)
    {
        trunk = swBuffer_new_trunk(conn->out_buffer, SW_TRUNK_SENDFILE, 0);
    }
    else
    {
        trunk = swBuffer_get_trunk(conn->out_buffer);
        if (trunk == NULL)
        {
            trunk = swBuffer_new_trunk(conn->out_buffer, SW_TRUNK_DATA, conn->out_buffer->trunk_size);
        }
    }
    return trunk;
}

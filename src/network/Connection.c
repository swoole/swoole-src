/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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
#include "Server.h"

#include <sys/stat.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL        0
#endif

static char *str_ptr = NULL;

int swConnection_onSendfile(swConnection *conn, swBuffer_trunk *chunk)
{
    int ret;
    swTask_sendfile *task = chunk->store.ptr;

#ifdef HAVE_TCP_NOPUSH
    if (task->offset == 0 && conn->tcp_nopush)
    {
        /**
         * disable tcp_nodelay
         */
        if (conn->tcp_nodelay)
        {
            int tcp_nodelay = 0;
            if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) == -1)
            {
                swWarn("setsockopt(TCP_NODELAY) failed. Error: %s[%d]", strerror(errno), errno);
            }
        }
        /**
         * enable tcp_nopush
         */
        if (swSocket_tcp_nopush(conn->fd, 1) == -1)
        {
            swWarn("swSocket_tcp_nopush() failed. Error: %s[%d]", strerror(errno), errno);
        }
    }
#endif

    int sendn = (task->filesize - task->offset > SW_SENDFILE_CHUNK_SIZE) ? SW_SENDFILE_CHUNK_SIZE : task->filesize - task->offset;
    ret = swoole_sendfile(conn->fd, task->fd, &task->offset, sendn);
    swTrace("ret=%d|task->offset=%ld|sendn=%d|filesize=%ld", ret, task->offset, sendn, task->filesize);

    if (ret <= 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("sendfile(%s, %ld, %d) failed.", task->filename, task->offset, sendn);
            swBuffer_pop_trunk(conn->out_buffer, chunk);
            return SW_OK;
        case SW_CLOSE:
            conn->close_wait = 1;
            return SW_ERR;
        default:
            break;
        }
    }

    //sendfile finish
    if (task->offset >= task->filesize)
    {
        swBuffer_pop_trunk(conn->out_buffer, chunk);

#ifdef HAVE_TCP_NOPUSH
        if (conn->tcp_nopush)
        {
            /**
             * disable tcp_nopush
             */
            if (swSocket_tcp_nopush(conn->fd, 0) == -1)
            {
                swWarn("swSocket_tcp_nopush() failed. Error: %s[%d]", strerror(errno), errno);
            }

            /**
             * enable tcp_nodelay
             */
            if (conn->tcp_nodelay)
            {
                int value = 1;
                if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &value, sizeof(int)) == -1)
                {
                    swWarn("setsockopt(TCP_NODELAY) failed. Error: %s[%d]", strerror(errno), errno);
                }
            }
        }
#endif
    }
    return SW_OK;
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
        return SW_OK;
    }

    ret = swConnection_send(conn, trunk->store.ptr + trunk->offset, sendn, 0);
    if (ret < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swWarn("send to fd[%d] failed. Error: %s[%d]", conn->fd, strerror(errno), errno);
            break;
        case SW_CLOSE:
            conn->close_errno = errno;
            conn->close_wait = 1;
            return SW_ERR;
        case SW_WAIT:
            conn->send_wait = 1;
            return SW_ERR;
        default:
            break;
        }
        return SW_OK;
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
    return SW_OK;
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

char* swConnection_get_ip(swConnection *conn)
{
    if (conn->socket_type == SW_SOCK_TCP)
    {
        return inet_ntoa(conn->info.addr.inet_v4.sin_addr);
    }
    else
    {
        if (str_ptr)
        {
            free(str_ptr);
        }
        char tmp[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &conn->info.addr.inet_v6.sin6_addr, tmp, sizeof(tmp)) == NULL)
        {
            return NULL;
        }
        else
        {
            str_ptr = strdup(tmp);
            return str_ptr;
        }
    }
}

int swConnection_get_port(swConnection *conn)
{
    if (conn->socket_type == SW_SOCK_TCP)
    {
        return ntohs(conn->info.addr.inet_v4.sin_port);
    }
    else
    {
        return ntohs(conn->info.addr.inet_v6.sin6_port);
    }
}

void swConnection_sendfile_destructor(swBuffer_trunk *chunk)
{
    swTask_sendfile *task = chunk->store.ptr;
    close(task->fd);
    sw_strdup_free(task->filename);
    sw_free(task);
}

int swConnection_sendfile(swConnection *conn, char *filename, off_t offset)
{
    if (conn->out_buffer == NULL)
    {
        conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
        if (conn->out_buffer == NULL)
        {
            return SW_ERR;
        }
    }

    swBuffer_trunk error_chunk;
    swTask_sendfile *task = sw_malloc(sizeof(swTask_sendfile));
    if (task == NULL)
    {
        swWarn("malloc for swTask_sendfile failed.");
        return SW_ERR;
    }
    bzero(task, sizeof(swTask_sendfile));

    task->filename = strdup(filename);
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        sw_strdup_free(task->filename);
        free(task);
        swSysError("open(%s) failed.", filename);
        return SW_ERR;
    }
    task->fd = file_fd;
    task->offset = offset;

    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0)
    {
        swSysError("fstat(%s) failed.", filename);
        error_chunk.store.ptr = task;
        swConnection_sendfile_destructor(&error_chunk);
        return SW_ERR;
    }
    task->filesize = file_stat.st_size;

    swBuffer_trunk *chunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_SENDFILE, 0);
    if (chunk == NULL)
    {
        swWarn("get out_buffer trunk failed.");
        error_chunk.store.ptr = task;
        swConnection_sendfile_destructor(&error_chunk);
        return SW_ERR;
    }

    chunk->store.ptr = (void *) task;
    chunk->destroy = swConnection_sendfile_destructor;

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

swBuffer_trunk* swConnection_get_in_buffer(swConnection *conn)
{
    swBuffer_trunk *trunk = NULL;
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
        trunk = swBuffer_new_trunk(buffer, SW_CHUNK_DATA, buffer->trunk_size);
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
            trunk = swBuffer_new_trunk(buffer, SW_CHUNK_DATA, buffer->trunk_size);
        }
    }
    return trunk;
}

swBuffer_trunk* swConnection_get_out_buffer(swConnection *conn, uint32_t type)
{
    swBuffer_trunk *trunk;
    if (conn->out_buffer == NULL)
    {
        conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
        if (conn->out_buffer == NULL)
        {
            return NULL;
        }
    }
    if (type == SW_CHUNK_SENDFILE)
    {
        trunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_SENDFILE, 0);
    }
    else
    {
        trunk = swBuffer_get_trunk(conn->out_buffer);
        if (trunk == NULL)
        {
            trunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_DATA, conn->out_buffer->trunk_size);
        }
    }
    return trunk;
}

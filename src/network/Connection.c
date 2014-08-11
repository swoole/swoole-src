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

int swConnection_send_string_buffer(swConnection *conn)
{
    int ret;
    swString *buffer = conn->object;
    swFactory *factory = SwooleG.factory;
    swDispatchData task;

    task.data.info.fd = conn->fd;
    task.data.info.from_id = conn->from_id;

#ifdef SW_USE_RINGBUFFER

    swServer *serv = SwooleG.serv;
    int target_worker_id = swServer_worker_schedule(serv, conn->fd);
    swWorker *worker = swServer_get_worker(serv, target_worker_id);
    swMemoryPool *pool = worker->pool_input;
    swPackage package;

    package.length = buffer->length;
    while (1)
    {
        package.data = pool->alloc(pool, buffer->length);
        if (package.data == NULL)
        {
            swYield();
            swWarn("reactor memory pool full.");
            continue;
        }
        break;
    }
    task.data.info.type = SW_EVENT_PACKAGE;
    task.data.info.len = sizeof(package);
    task.target_worker_id = target_worker_id;
    //swoole_dump_bin(package.data, 's', buffer->length);
    memcpy(package.data, buffer->str, buffer->length);
    memcpy(task.data.data, &package, sizeof(package));
    ret = factory->dispatch(factory, &task);

#else
    int send_n = buffer->length;
    task.data.info.type = SW_EVENT_PACKAGE_START;
    task.target_worker_id = -1;

    /**
     * lock target
     */
    SwooleTG.factory_lock_target = 1;

    void *send_ptr = buffer->str;
    do
    {
        if (send_n > SW_BUFFER_SIZE)
        {
            task.data.info.len = SW_BUFFER_SIZE;
            memcpy(task.data.data, send_ptr, SW_BUFFER_SIZE);
        }
        else
        {
            task.data.info.type = SW_EVENT_PACKAGE_END;
            task.data.info.len = send_n;
            memcpy(task.data.data, send_ptr, send_n);
        }

        swTrace("dispatch, type=%d|len=%d\n", _send.info.type, _send.info.len);

        ret = factory->dispatch(factory, &task);
        //TODO: 处理数据失败，数据将丢失
        if (ret < 0)
        {
            swWarn("factory->dispatch failed.");
        }
        send_n -= task.data.info.len;
        send_ptr += task.data.info.len;
    }
    while (send_n > 0);

    /**
     * unlock
     */
    SwooleTG.factory_target_worker = -1;
    SwooleTG.factory_lock_target = 0;

#endif
    return ret;
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

int swConnection_send_in_buffer(swConnection *conn)
{
    swDispatchData task;
    swFactory *factory = SwooleG.factory;

    task.data.info.fd = conn->fd;
    task.data.info.from_id = conn->from_id;

    swBuffer *buffer = conn->in_buffer;
    swBuffer_trunk *trunk = swBuffer_get_trunk(buffer);

#ifdef SW_USE_RINGBUFFER

    swServer *serv = SwooleG.serv;
    uint16_t target_worker_id = swServer_worker_schedule(serv, conn->fd);
    swWorker *worker = swServer_get_worker(serv, target_worker_id);
    swMemoryPool *pool = worker->pool_input;
    swPackage package;

    package.length = 0;
    while (1)
    {
        package.data = pool->alloc(pool, buffer->length);
        if (package.data == NULL)
        {
            swYield();
            swWarn("reactor memory pool full.");
            continue;
        }
        break;
    }
    task.data.info.type = SW_EVENT_PACKAGE;

    while (trunk != NULL)
    {
        task.data.info.len = trunk->length;
        memcpy(package.data + package.length, trunk->store.ptr, trunk->length);
        package.length += trunk->length;

        swBuffer_pop_trunk(buffer, trunk);
        trunk = swBuffer_get_trunk(buffer);
    }
    task.data.info.len = sizeof(package);
    task.target_worker_id = target_worker_id;
    memcpy(task.data.data, &package, sizeof(package));
    //swWarn("[ReactorThread] copy_n=%d", package.length);
    return factory->dispatch(factory, &task);

#else

    int ret;
    task.data.info.type = SW_EVENT_PACKAGE_START;
    task.target_worker_id = -1;

    /**
     * lock target
     */
    SwooleTG.factory_lock_target = 1;

    while (trunk != NULL)
    {
        task.data.info.len = trunk->length;
        memcpy(task.data.data, trunk->store.ptr, task.data.info.len);
        //package end
        if (trunk->next == NULL)
        {
            task.data.info.type = SW_EVENT_PACKAGE_END;
        }
        ret = factory->dispatch(factory, &task);
        //TODO: 处理数据失败，数据将丢失
        if (ret < 0)
        {
            swWarn("factory->dispatch() failed.");
        }
        swBuffer_pop_trunk(buffer, trunk);
        trunk = swBuffer_get_trunk(buffer);

        swTrace("send2worker[trunk_num=%d][type=%d]\n", buffer->trunk_num, _send.info.type);
    }
    /**
     * unlock
     */
    SwooleTG.factory_target_worker = -1;
    SwooleTG.factory_lock_target = 0;

#endif
    return SW_OK;
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

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
#include "buffer.h"

/**
 * create new buffer
 */
swBuffer* swBuffer_new(int trunk_size)
{
    swBuffer *buffer = sw_malloc(sizeof(swBuffer));
    if (buffer == NULL)
    {
        swWarn("malloc for buffer failed. Error: %s[%d]", strerror(errno), errno);
        return NULL;
    }

    bzero(buffer, sizeof(swBuffer));
    buffer->trunk_size = trunk_size;

    return buffer;
}

/**
 * create new trunk
 */
swBuffer_trunk *swBuffer_new_trunk(swBuffer *buffer, uint32_t type, uint32_t size)
{
    swBuffer_trunk *chunk = sw_malloc(sizeof(swBuffer_trunk));
    if (chunk == NULL)
    {
        swWarn("malloc for trunk failed. Error: %s[%d]", strerror(errno), errno);
        return NULL;
    }

    bzero(chunk, sizeof(swBuffer_trunk));

    //require alloc memory
    if (type == SW_CHUNK_DATA && size > 0)
    {
        void *buf = sw_malloc(size);
        if (buf == NULL)
        {
            swWarn("malloc(%d) for data failed. Error: %s[%d]", size, strerror(errno), errno);
            sw_free(chunk);
            return NULL;
        }
        chunk->size = size;
        chunk->store.ptr = buf;
    }

    chunk->type = type;
    buffer->trunk_num ++;

    if (buffer->head == NULL)
    {
        buffer->tail = buffer->head = chunk;
    }
    else
    {
        buffer->tail->next = chunk;
        buffer->tail = chunk;
    }

    return chunk;
}

/**
 * pop the head chunk
 */
void swBuffer_pop_trunk(swBuffer *buffer, swBuffer_trunk *chunk)
{
    if (chunk->next == NULL)
    {
        buffer->head = NULL;
        buffer->tail = NULL;
        buffer->length = 0;
        buffer->trunk_num = 0;
    }
    else
    {
        buffer->head = chunk->next;
        buffer->length -= chunk->length;
        buffer->trunk_num--;
    }
    if (chunk->type == SW_CHUNK_DATA)
    {
        sw_free(chunk->store.ptr);
    }
    if (chunk->destroy)
    {
        chunk->destroy(chunk);
    }
    sw_free(chunk);
}

/**
 * free buffer
 */
int swBuffer_free(swBuffer *buffer)
{
    volatile swBuffer_trunk *chunk = buffer->head;
    void * *will_free_trunk;  //free the point
    while (chunk != NULL)
    {
        if (chunk->type == SW_CHUNK_DATA)
        {
            sw_free(chunk->store.ptr);
        }
        will_free_trunk = (void *) chunk;
        chunk = chunk->next;
        sw_free(will_free_trunk);
    }
    sw_free(buffer);
    return SW_OK;
}

/**
 * append to buffer queue
 */
int swBuffer_append(swBuffer *buffer, void *data, uint32_t size)
{
    swBuffer_trunk *chunk = swBuffer_new_trunk(buffer, SW_CHUNK_DATA, size);
    if (chunk == NULL)
    {
        return SW_ERR;
    }

    buffer->length += size;
    chunk->length = size;

    memcpy(chunk->store.ptr, data, size);

    swTraceLog(SW_TRACE_BUFFER, "trunk_n=%d|size=%d|trunk_len=%d|trunk=%p", buffer->trunk_num, size,
            chunk->length, chunk);

    return SW_OK;
}

/**
 * print buffer
 */
void swBuffer_debug(swBuffer *buffer, int print_data)
{
    int i = 0;
    volatile swBuffer_trunk *trunk = buffer->head;
    printf("%s\n%s\n", SW_START_LINE, __func__);
    while (trunk != NULL)
    {
        i++;
        printf("%d.\tlen=%d", i, trunk->length);
        if (print_data)
        {
            printf("\tdata=%s", (char *) trunk->store.ptr);
        }
        printf("\n");
        trunk = trunk->next;
    }
    printf("%s\n%s\n", SW_END_LINE, __func__);
}

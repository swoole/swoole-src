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

#ifndef SW_BUFFER_H_
#define SW_BUFFER_H_

SW_EXTERN_C_BEGIN

enum swBufferChunk
{
    SW_CHUNK_DATA,
    SW_CHUNK_SENDFILE,
    SW_CHUNK_CLOSE,
};

typedef struct _swBuffer_chunk
{
    uint32_t type;
    uint32_t length;
    uint32_t offset;
    union
    {
        void *ptr;
        struct
        {
            uint32_t val1;
            uint32_t val2;
        } data;
    } store;
    uint32_t size;
    void (*destroy)(struct _swBuffer_chunk *chunk);
    struct _swBuffer_chunk *next;
} swBuffer_chunk;

typedef struct _swBuffer
{
    int fd;
    uint32_t chunk_num;
    /**
     * 0: donot use chunk
     */
    uint32_t chunk_size;
    uint32_t length;
    swBuffer_chunk *head;
    swBuffer_chunk *tail;
} swBuffer;

#define swBuffer_get_chunk(buffer)   (buffer->head)
#define swBuffer_empty(buffer)       (buffer == nullptr || buffer->head == nullptr)

swBuffer* swBuffer_new(uint32_t chunk_size);
swBuffer_chunk *swBuffer_new_chunk(swBuffer *buffer, uint32_t type, uint32_t size);
void swBuffer_pop_chunk(swBuffer *buffer, swBuffer_chunk *chunk);
int swBuffer_append(swBuffer *buffer, const void *data, uint32_t size);

void swBuffer_debug(swBuffer *buffer, int print_data);
int swBuffer_free(swBuffer *buffer);

SW_EXTERN_C_END

#endif /* SW_BUFFER_H_ */

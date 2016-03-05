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

#ifdef __cplusplus
extern "C"
{
#endif

enum swBufferChunk
{
    SW_CHUNK_DATA,
    SW_CHUNK_SENDFILE,
    SW_CHUNK_CLOSE,
};

typedef struct _swBuffer_trunk
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
    void (*destroy)(struct _swBuffer_trunk *chunk);
    struct _swBuffer_trunk *next;
} swBuffer_trunk;

typedef struct _swBuffer
{
    int fd;
    uint8_t trunk_num; //trunk数量
    uint16_t trunk_size;
    uint32_t length;
    swBuffer_trunk *head;
    swBuffer_trunk *tail;
} swBuffer;

#define swBuffer_get_trunk(buffer)   (buffer->head)
#define swBuffer_empty(buffer)       (buffer == NULL || buffer->head == NULL)

swBuffer* swBuffer_new(int trunk_size);
swBuffer_trunk *swBuffer_new_trunk(swBuffer *buffer, uint32_t type, uint32_t size);
void swBuffer_pop_trunk(swBuffer *buffer, swBuffer_trunk *trunk);
int swBuffer_append(swBuffer *buffer, void *data, uint32_t size);

void swBuffer_debug(swBuffer *buffer, int print_data);
int swBuffer_free(swBuffer *buffer);

#ifdef __cplusplus
}
#endif

#endif /* SW_BUFFER_H_ */

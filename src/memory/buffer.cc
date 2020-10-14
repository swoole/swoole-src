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
#include "swoole_buffer.h"
namespace swoole {

Buffer::Buffer(uint32_t _chunk_size) {
    chunk_size = _chunk_size == 0 ? INT_MAX : _chunk_size;
}

BufferChunk *Buffer::alloc(BufferChunk::Type type, uint32_t size) {
    BufferChunk *chunk = new BufferChunk();

    if (type == BufferChunk::TYPE_DATA && size > 0) {
        chunk->size = size;
        chunk->value.ptr = new char[size];
    }

    chunk->type = type;
    queue_.push(chunk);

    return chunk;
}

void Buffer::pop() {
    BufferChunk *chunk = queue_.front();

    total_length -= chunk->size;
    if (chunk->type == BufferChunk::TYPE_DATA) {
        delete[] chunk->value.ptr;
    }
    if (chunk->destroy) {
        chunk->destroy(chunk);
    }
    delete chunk;
    queue_.pop();
}

Buffer::~Buffer() {
    while (!queue_.empty()) {
        pop();
    }
}

void Buffer::append(const void *data, uint32_t size) {
    uint32_t _length = size;
    char *_pos = (char *) data;
    uint32_t _n;

    // buffer enQueue
    while (_length > 0) {
        _n = _length >= chunk_size ? chunk_size : _length;

        BufferChunk *chunk = alloc(BufferChunk::TYPE_DATA, _n);

        total_length += _n;

        memcpy(chunk->value.ptr, _pos, _n);
        chunk->length = _n;

        swTraceLog(SW_TRACE_BUFFER, "chunk_n=%d|size=%d|chunk_len=%d|chunk=%p", count(), _n, chunk->length, chunk);

        _pos += _n;
        _length -= _n;
    }
}

}  // namespace swoole

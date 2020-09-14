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

#pragma once

#include <queue>

namespace swoole {

struct BufferChunk {
    enum Type {
        TYPE_DATA,
        TYPE_SENDFILE,
        TYPE_CLOSE,
    };

    Type type;
    uint32_t length;
    uint32_t offset;
    union {
        char *ptr;
        void *object;
        struct {
            uint32_t val1;
            uint32_t val2;
        } data;
    } value;
    uint32_t size;
    void (*destroy)(BufferChunk *chunk);
};

class Buffer {
  private:
    // 0: donot use chunk
    uint32_t chunk_size;
    uint32_t total_length = 0;
    std::queue<BufferChunk *> queue_;

  public:
    Buffer(uint32_t chunk_size);
    ~Buffer();

    BufferChunk *alloc(BufferChunk::Type type, uint32_t size);

    BufferChunk *front() {
        return queue_.front();
    }

    void pop();
    void append(const void *data, uint32_t size);

    uint32_t length() {
        return total_length;
    }

    size_t count() {
        return queue_.size();
    }

    bool empty() {
        return queue_.empty();
    }
};

static inline bool empty_buffer(Buffer *buffer) {
    return buffer == nullptr || buffer->empty();
}
}  // namespace swoole

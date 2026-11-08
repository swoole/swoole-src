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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "swoole_buffer.h"

#include <memory>
#include <stdexcept>

namespace swoole {

BufferChunk::BufferChunk(Type type, uint32_t size) : type(type), size(size) {
    if (type == TYPE_DATA && size > 0) {
        value.str = new char[size];
    }
}

BufferChunk::~BufferChunk() {
    if (type == TYPE_DATA) {
        delete[] value.str;
    }
    if (destroy) {
        destroy(this);
    }
}

Buffer::Buffer(uint32_t _chunk_size) {
    chunk_size = _chunk_size == 0 ? INT_MAX : _chunk_size;
}

BufferChunk *Buffer::alloc(BufferChunk::Type type, uint32_t size) {
    auto chunk = std::make_unique<BufferChunk>(type, size);
    queue_.push(chunk.get());
    return chunk.release();
}

void Buffer::pop() {
    BufferChunk *chunk = queue_.front();
    total_length -= chunk->length;
    delete chunk;
    queue_.pop();
}

Buffer::~Buffer() {
    while (!queue_.empty()) {
        pop();
    }
}

void Buffer::append(const char *data, uint32_t size) {
    uint32_t _length = size;
    auto _pos = data;

    if (sw_unlikely(size == 0)) {
        throw std::invalid_argument("buffer append size must be positive");
    }
    if (sw_unlikely(size > UINT32_MAX - total_length)) {
        throw std::length_error("buffer length exceeds UINT32_MAX");
    }

    // buffer enQueue
    while (_length > 0) {
        uint32_t _n = _length >= chunk_size ? chunk_size : _length;

        BufferChunk *chunk = alloc(BufferChunk::TYPE_DATA, _n);

        total_length += _n;

        memcpy(chunk->value.str, _pos, _n);
        chunk->length = _n;

        swoole_trace_log(
            SW_TRACE_BUFFER, "chunk_n=%lu|size=%u|chunk_len=%u|chunk=%p", count(), _n, chunk->length, chunk);

        _pos += _n;
        _length -= _n;
    }
}

void Buffer::append(const iovec *iov, size_t iovcnt, off_t offset) {
    if (sw_unlikely(iovcnt == 0)) {
        return;
    }

    size_t length = 0;
    for (size_t i = 0; i < iovcnt; i++) {
        if (sw_unlikely(iov[i].iov_len == 0)) {
            throw std::invalid_argument("iovec entry length must be positive");
        }
        assert(iov[i].iov_base != nullptr);
        if (sw_unlikely(iov[i].iov_len > SIZE_MAX - length)) {
            throw std::length_error("iovec length overflows size_t");
        }
        length += iov[i].iov_len;
    }

    if (sw_unlikely(offset < 0 || static_cast<uintmax_t>(offset) >= length)) {
        return;
    }
    size_t skip = static_cast<size_t>(offset);
    size_t remaining = length - skip;
    if (sw_unlikely(remaining > UINT32_MAX - total_length)) {
        throw std::length_error("buffer length exceeds UINT32_MAX");
    }

    BufferChunk *chunk = nullptr;
    for (size_t i = 0; i < iovcnt; i++) {
        if (skip >= iov[i].iov_len) {
            skip -= iov[i].iov_len;
            continue;
        }
        auto *pos = static_cast<const char *>(iov[i].iov_base) + skip;
        size_t span = iov[i].iov_len - skip;
        skip = 0;

        while (span > 0) {
            if (chunk == nullptr || chunk->length == chunk->size) {
                const auto capacity = static_cast<uint32_t>(std::min<size_t>(remaining, chunk_size));
                chunk = alloc(BufferChunk::TYPE_DATA, capacity);
            }
            const auto bytes = static_cast<uint32_t>(std::min<size_t>(span, chunk->size - chunk->length));
            memcpy(chunk->value.str + chunk->length, pos, bytes);
            chunk->length += bytes;
            total_length += bytes;
            remaining -= bytes;
            span -= bytes;
            pos += bytes;

            swoole_trace_log(
                SW_TRACE_BUFFER, "chunk_n=%zu|size=%u|chunk_len=%u|chunk=%p", count(), bytes, chunk->length, chunk);
        }
    }
}
}  // namespace swoole

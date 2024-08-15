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

#pragma once

#include "swoole_api.h"
#include "swoole_string.h"
#include "swoole_socket.h"

#include <unordered_map>

namespace swoole {

struct PipeBuffer {
    DataHead info;
    char data[0];

    bool is_begin() {
        return info.flags & SW_EVENT_DATA_BEGIN;
    }

    bool is_chunked() {
        return info.flags & SW_EVENT_DATA_CHUNK;
    }

    bool is_end() {
        return info.flags & SW_EVENT_DATA_END;
    }
};

struct PacketPtr {
    size_t length;
    char *data;
};

struct DgramPacket {
    SocketType socket_type;
    network::Address socket_addr;
    uint32_t length;
    char data[0];
};

struct PacketTask {
    size_t length;
    char tmpfile[SW_TASK_TMP_PATH_SIZE];
};

class MessageBus {
  private:
    const Allocator *allocator_;
    std::unordered_map<uint64_t, std::shared_ptr<String>> packet_pool_;
    std::vector<network::Socket *> pipe_sockets_;
    std::function<uint64_t(void)> id_generator_;
    size_t buffer_size_;
    PipeBuffer *buffer_ = nullptr;
    bool always_chunked_transfer_ = false;

    String *get_packet_buffer();
    ReturnCode prepare_packet(uint16_t &recv_chunk_count, String *packet_buffer);

  public:
    MessageBus() {
        allocator_ = sw_std_allocator();
        buffer_size_ = SW_BUFFER_SIZE_STD;
    }

    ~MessageBus();

    bool empty() {
        return packet_pool_.empty();
    }

    size_t count() {
        return packet_pool_.size();
    }

    void clear() {
        packet_pool_.clear();
    }

    void set_allocator(const Allocator *allocator) {
        allocator_ = allocator;
    }

    void set_id_generator(const std::function<uint64_t(void)> &id_generator) {
        id_generator_ = id_generator;
    }

    void set_buffer_size(size_t buffer_size) {
        buffer_size_ = buffer_size;
    }

    void set_always_chunked_transfer() {
        always_chunked_transfer_ = true;
    }

    size_t get_buffer_size() {
        return buffer_size_;
    }

    size_t get_memory_size();

    bool alloc_buffer() {
        void *_ptr = allocator_->malloc(sizeof(*buffer_) + buffer_size_);
        if (_ptr) {
            buffer_ = (PipeBuffer *) _ptr;
            sw_memset_zero(&buffer_->info, sizeof(buffer_->info));
            return true;
        } else {
            return false;
        }
    }

    /**
     * If use the zend_string_allocator, must manually call this function to release the memory,
     * otherwise coredump will occur when php shutdown, because zend_string has been released
     */
    void free_buffer() {
        allocator_->free(buffer_);
        buffer_ = nullptr;
    }

    void pass(SendData *task) {
        memcpy(&buffer_->info, &task->info, sizeof(buffer_->info));
        if (task->info.len > 0) {
            buffer_->info.flags = SW_EVENT_DATA_PTR;
            PacketPtr pkt{task->info.len, (char *) task->data};
            buffer_->info.len = sizeof(pkt);
            memcpy(buffer_->data, &pkt, sizeof(pkt));
        }
    }

    /**
     * Send data to socket. If the data sent is larger than Server::ipc_max_size, then it is sent in chunks.
     * Otherwise send it directly.
     * When sending data in multi-thread environment, must use get_pipe_socket() to separate socket memory.
     * @return: send success returns true, send failure returns false.
     */
    bool write(network::Socket *sock, SendData *packet);
    /**
     * Receive data from socket, if only one chunk is received, packet will be saved in packet_pool.
     * Then continue to listen to readable events, waiting for more chunks.
     * @return: >0: receive a complete packet, 0: continue to wait for data, -1: an error occurred
     */
    ssize_t read(network::Socket *sock);
    /**
     * Receive data from pipeline, and store data to buffer
     * @return: >0: receive a complete packet, 0: continue to wait for data, -1: an error occurred
     */
    ssize_t read_with_buffer(network::Socket *sock);
    /**
     * The last chunk of data has been received, return address and length, start processing this packet.
     */
    PacketPtr get_packet() const;
    PipeBuffer *get_buffer() {
        return buffer_;
    }
    /**
     * Pop the data memory address to the outer layer, no longer managed by MessageBus
     */
    char *move_packet() {
        uint64_t msg_id = buffer_->info.msg_id;
        auto iter = packet_pool_.find(msg_id);
        if (iter != packet_pool_.end()) {
            auto str = iter->second.get();
            char *val = str->str;
            str->str = nullptr;
            return val;
        } else {
            return nullptr;
        }
    }
    /**
     * The processing of this data packet has been completed, and the relevant memory has been released
     */
    void pop() {
        if (buffer_->is_end()) {
            packet_pool_.erase(buffer_->info.msg_id);
        }
    }
    /**
     * It is possible to operate the same pipe in multiple threads.
     * Each thread must have a unique buffer and the socket memory must be separated.
     */
    network::Socket *get_pipe_socket(network::Socket *sock) {
        return pipe_sockets_[sock->get_fd()];
    }
    void init_pipe_socket(network::Socket *sock);
};
}  // namespace swoole

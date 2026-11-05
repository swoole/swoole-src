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

#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_protocol.h"

#include <unordered_map>

namespace swoole {
/**
 * The memory layout of an IPC packet: a DataHead followed by the payload.
 * A payload larger than the buffer is transferred in chunks, which are marked with
 * SW_EVENT_DATA_BEGIN/SW_EVENT_DATA_CHUNK/SW_EVENT_DATA_END in info.flags.
 */
struct PipeBuffer {
    DataHead info;
    char data[0];

    bool is_begin() const {
        return info.flags & SW_EVENT_DATA_BEGIN;
    }

    bool is_chunked() const {
        return info.flags & SW_EVENT_DATA_CHUNK;
    }

    bool is_end() const {
        return info.flags & SW_EVENT_DATA_END;
    }
};

/**
 * A pointer to the payload of a task, used to pass the data in-process without copying.
 */
struct PacketPtr {
    size_t length;
    char *data;
};

/**
 * The header of a received datagram packet, followed by the payload.
 */
struct DgramPacket {
    SocketType socket_type;
    network::Address socket_addr;
    uint32_t length;
    char data[0];
};

/**
 * The payload of a task which is too large for IPC, the data is stored in a tmpfile.
 */
struct PacketTask {
    size_t length;
    char tmpfile[SW_TASK_TMP_PATH_SIZE];
};

/**
 * MessageBus is the IPC layer used to exchange packets between the master, the reactor
 * threads/processes and the workers through unix sockets.
 *
 * A packet larger than the buffer is sent in chunks, the receiver accumulates the chunks
 * in packet_pool_ and notifies the upper layer when the last chunk has been received.
 * Each thread/process owns its own MessageBus and its own buffer.
 */
class MessageBus {
  private:
    /**
     * Allocator of the strings in packet_pool_. It can be sw_zend_string_allocator(),
     * because the packet memory may be moved to the PHP layer by move_packet().
     * Notice: buffer_ does NOT use this allocator.
     */
    const Allocator *allocator_;
    /**
     * The chunks of the packets which are being received, indexed by msg_id.
     * The entry is created by the first chunk(is_begin()) and erased by pop() after
     * the packet has been processed.
     */
    std::unordered_map<uint64_t, std::shared_ptr<String>> packet_pool_;
    /**
     * Socket object per pipe fd, see init_pipe_socket()/get_pipe_socket().
     */
    std::vector<network::Socket *> pipe_sockets_;
    /**
     * Generates the unique id of each sent packet, it is used to match the chunks
     * belonging to the same packet.
     */
    std::function<uint64_t(void)> id_generator_;
    /**
     * Size of buffer_, it is also the max size of an IPC packet. A larger packet is sent
     * in chunks of (buffer_size_ - sizeof(DataHead)) bytes.
     */
    size_t buffer_size_;
    /**
     * The internal scratch buffer used to receive/assemble a packet, allocated by
     * alloc_buffer(). It is never exposed to the PHP layer.
     */
    PipeBuffer *buffer_ = nullptr;
    /**
     * Always send the data in chunked mode, even if it fits in a single packet.
     */
    bool always_chunked_transfer_ = false;

    /**
     * Find or create the accumulation buffer of the packet which is being received.
     * @return nullptr if the first received chunk is not marked with SW_EVENT_DATA_BEGIN
     *         (abnormal pipeline data), the caller must discard the data.
     */
    String *get_packet_buffer();
    /**
     * Handle one received chunk of the current packet.
     * @param recv_chunk_count number of the chunks received in the current event loop round
     * @return SW_READY: the last chunk has been received, SW_CONTINUE: keep reading,
     *         SW_WAIT: the consecutive chunk limit is reached, return to the event loop
     */
    ReturnCode prepare_packet(uint16_t &recv_chunk_count, String *packet_buffer);

  public:
    /**
     * Create a message bus using the default allocator and the default buffer size.
     */
    MessageBus() {
        allocator_ = sw_std_allocator();
        buffer_size_ = SW_BUFFER_SIZE_STD;
    }

    ~MessageBus();

    /**
     * Whether there is any unprocessed packet in packet_pool_.
     */
    bool empty() const {
        return packet_pool_.empty();
    }

    /**
     * Number of the unprocessed packets in packet_pool_.
     */
    size_t count() const {
        return packet_pool_.size();
    }

    /**
     * Drop all the unprocessed packets.
     */
    void clear() {
        packet_pool_.clear();
    }

    /**
     * Set the allocator of the strings in packet_pool_, it has no effect on buffer_.
     * In the PHP extension it is usually set to sw_zend_string_allocator(), since the
     * packet memory may be moved to the PHP layer by move_packet().
     */
    void set_allocator(const Allocator *allocator) {
        allocator_ = allocator;
    }

    /**
     * Set the generator of msg_id. It must be shared by all the processes/threads to
     * keep the id globally unique.
     */
    void set_id_generator(const std::function<uint64_t(void)> &id_generator) {
        id_generator_ = id_generator;
    }

    /**
     * Set the max size of an IPC packet, it must be called before alloc_buffer().
     * Notice: changing it after the buffer has been allocated will make the buffer size
     * inconsistent with the value used by read()/write().
     */
    void set_buffer_size(size_t buffer_size) {
        buffer_size_ = buffer_size;
    }

    /**
     * Always send the data in chunked mode, even if it fits in a single packet, so that
     * all the packets are reassembled from packet_pool_ on the receiving side.
     * It is used by the message buses of the thread mode(reactor thread/worker threads).
     */
    void set_always_chunked_transfer() {
        always_chunked_transfer_ = true;
    }

    /**
     * Get the max size of an IPC packet, same as the size of buffer_.
     */
    size_t get_buffer_size() const {
        return buffer_size_;
    }

    /**
     * Get the total memory used by the message bus(the internal buffer and packet_pool_).
     */
    size_t get_memory_size() const;
    /**
     * Allocate buffer_ with buffer_size_ bytes. It is a no-op if the buffer has already
     * been allocated, throws std::bad_alloc on failure.
     */
    void alloc_buffer();

    /**
     * The buffer is the internal scratch memory of MessageBus, it is never exposed to PHP,
     * so it does not use the allocator(set by set_allocator), must be released manually.
     */
    void free_buffer() {
        if (buffer_ == nullptr) {
            return;
        }
        delete[] reinterpret_cast<char *>(buffer_);
        buffer_ = nullptr;
    }

    /**
     * Fill buffer_ with the task directly, without sending it over a socket, it is used
     * for the in-process dispatch(base mode/thread mode). The data is marked with
     * SW_EVENT_DATA_PTR and will be returned by get_packet().
     */
    void pass(const SendData *task) const;

    /**
     * Send data to socket. If the data sent is larger than Server::ipc_max_size, then it is sent in chunks.
     * Otherwise, send it directly.
     * When sending data in multi-thread environment, must use get_pipe_socket() to separate socket memory.
     * @return: send success returns true, send failure returns false.
     */
    bool write(network::Socket *sock, SendData *packet) const;
    /**
     * Receive data from socket, if only one chunk is received, packet will be saved in packet_pool.
     * Then continue to listen to readable events, waiting for more chunks.
     * @return: >0: receive a complete packet, 0: continue to wait for data, -1: an error occurred
     */
    ssize_t read(network::Socket *sock);
    /**
     * Receive a packet by reading it into buffer_ directly(only for the dgram type socket,
     * where each read returns a complete packet). If the packet is chunked, the payload is
     * accumulated in packet_pool_ instead of buffer_.
     * @return: >0: receive a complete packet, 0: continue to wait for data, -1: an error occurred
     */
    ssize_t read_with_buffer(network::Socket *sock);
    /**
     * The last chunk of data has been received, return address and length, start processing this packet.
     * Notice: the returned address may point to the memory of packet_pool_, not to buffer_.
     */
    PacketPtr get_packet() const;
    /**
     * Get the internal buffer. Notice: the caller must ensure that alloc_buffer() has
     * been called, the buffer will not be allocated on demand.
     */
    PipeBuffer *get_buffer() const {
        return buffer_;
    }
    /**
     * Pop the data memory address to the outer layer, no longer managed by MessageBus.
     * The ownership of the packet memory is transferred to the caller(used by the PHP
     * layer, which wraps it as a zend_string).
     */
    char *move_packet();
    /**
     * The processing of this data packet has been completed, and the relevant memory has been released.
     * It only drops the accumulated chunks of the packet whose END flag has been received.
     */
    void pop() {
        if (buffer_->is_end()) {
            packet_pool_.erase(buffer_->info.msg_id);
        }
    }
    /**
     * Get the dedicated socket object of the given pipe fd for the current thread.
     * It is possible to operate the same pipe in multiple threads.
     * Each thread must have a unique buffer and the socket memory must be separated.
     */
    network::Socket *get_pipe_socket(const network::Socket *sock) const {
        return pipe_sockets_[sock->get_fd()];
    }
    /**
     * Create the socket object of the given pipe fd, see get_pipe_socket().
     */
    void init_pipe_socket(const network::Socket *sock);
    /**
     * Free socket objects created by init_pipe_socket() without closing the pipe fds.
     */
    void release_pipe_sockets();
};
}  // namespace swoole

#include "swoole_server.h"

#include <assert.h>

using swoole::network::Address;
using swoole::network::Socket;

namespace swoole {

PacketPtr MessageBus::get_packet() const {
    PacketPtr pkt;
    if (buffer_->info.flags & SW_EVENT_DATA_PTR) {
        memcpy(&pkt, buffer_->data, sizeof(pkt));
    } else if (buffer_->info.flags & SW_EVENT_DATA_OBJ_PTR) {
        String *object;
        memcpy(&object, buffer_->data, sizeof(object));
        pkt.data = object->str;
        pkt.length = object->length;
    } else {
        pkt.data = buffer_->data;
        pkt.length = buffer_->info.len;
    }

    return pkt;
}

String *MessageBus::get_packet_buffer() {
    String *packet_buffer = nullptr;

    auto iter = packet_pool_.find(buffer_->info.msg_id);
    if (iter == packet_pool_.end()) {
        if (!buffer_->is_begin()) {
            return nullptr;
        }
        packet_buffer = make_string(buffer_->info.len, allocator_);
        packet_pool_.emplace(buffer_->info.msg_id, std::shared_ptr<String>(packet_buffer));
    } else {
        packet_buffer = iter->second.get();
    }

    return packet_buffer;
}

ReturnCode MessageBus::prepare_packet(uint16_t &recv_chunk_count, String *packet_buffer) {
    recv_chunk_count++;
    if (!buffer_->is_end()) {
        /**
         * if the reactor thread sends too many chunks to the worker process,
         * the worker process may receive chunks all the time,
         * resulting in the worker process being unable to handle other tasks.
         * in order to make the worker process handle tasks fairly,
         * the maximum number of consecutive chunks received by the worker is limited.
         */
        if (recv_chunk_count >= SW_WORKER_MAX_RECV_CHUNK_COUNT) {
            swoole_trace_log(SW_TRACE_WORKER,
                             "worker process[%u] receives the chunk data to the maximum[%d], return to event loop",
                             SwooleG.process_id,
                             recv_chunk_count);
            return SW_WAIT;
        }
        return SW_CONTINUE;
    } else {
        /**
         * Because we don't want to split the EventData parameters into DataHead and data,
         * we store the value of the worker_buffer pointer in EventData.data.
         * The value of this pointer will be fetched in the Server::get_pipe_packet() function.
         */
        buffer_->info.flags |= SW_EVENT_DATA_OBJ_PTR;
        memcpy(buffer_->data, &packet_buffer, sizeof(packet_buffer));
        swoole_trace("msg_id=%ld, len=%u", buffer_->info.msg_id, buffer_->info.len);

        return SW_READY;
    }
}

ssize_t MessageBus::read(Socket *sock) {
    ssize_t recv_n = 0;
    uint16_t recv_chunk_count = 0;
    DataHead *info = &buffer_->info;
    struct iovec buffers[2];

_read_from_pipe:
    recv_n = recv(sock->get_fd(), info, sizeof(buffer_->info), MSG_PEEK);
    if (recv_n < 0) {
        if (sock->catch_read_error(errno) == SW_WAIT) {
            return SW_OK;
        }
        return SW_ERR;
    } else if (recv_n == 0) {
        swoole_warning("receive data from socket#%d returns 0", sock->get_fd());
        return SW_ERR;
    }

    if (!buffer_->is_chunked()) {
        return sock->read(buffer_, sizeof(buffer_->info) + buffer_->info.len);
    }

    auto packet_buffer = get_packet_buffer();
    if (packet_buffer == nullptr) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SERVER_WORKER_ABNORMAL_PIPE_DATA,
                         "abnormal pipeline data, msg_id=%ld, pipe_fd=%d, reactor_id=%d",
                         info->msg_id,
                         sock->get_fd(),
                         info->reactor_id);
        return SW_OK;
    }

    size_t remain_len = buffer_->info.len - packet_buffer->length;
    buffers[0].iov_base = info;
    buffers[0].iov_len = sizeof(buffer_->info);
    buffers[1].iov_base = packet_buffer->str + packet_buffer->length;
    buffers[1].iov_len = SW_MIN(buffer_size_ - sizeof(buffer_->info), remain_len);

    recv_n = readv(sock->get_fd(), buffers, 2);
    if (recv_n == 0) {
        swoole_warning("receive pipeline data error, pipe_fd=%d, reactor_id=%d", sock->get_fd(), info->reactor_id);
        return SW_ERR;
    }
    if (recv_n < 0 && sock->catch_read_error(errno) == SW_WAIT) {
        return SW_OK;
    }
    if (recv_n > 0) {
        packet_buffer->length += (recv_n - sizeof(buffer_->info));
        swoole_trace("append msgid=%ld, buffer=%p, n=%ld", buffer_->info.msg_id, packet_buffer, recv_n);
    }

    switch (prepare_packet(recv_chunk_count, packet_buffer)) {
    case SW_READY:
        return recv_n;
    case SW_CONTINUE:
        goto _read_from_pipe;
    case SW_WAIT:
        return SW_OK;
    default:
        assert(0);
        return SW_ERR;
    }
}

/**
 * Notice: only supports dgram type socket
 */
ssize_t MessageBus::read_with_buffer(network::Socket *sock) {
    ssize_t recv_n;
    uint16_t recv_chunk_count = 0;

_read_from_pipe:
    recv_n = sock->read(buffer_, buffer_size_);
    if (recv_n < 0) {
        if (sock->catch_read_error(errno) == SW_WAIT) {
            return SW_OK;
        }
        return SW_ERR;
    } else if (recv_n == 0) {
        swoole_warning("receive data from socket#%d returns 0", sock->get_fd());
        return SW_ERR;
    }

    recv_chunk_count++;

    if (!buffer_->is_chunked()) {
        return recv_n;
    }

    String *packet_buffer = get_packet_buffer();
    if (packet_buffer == nullptr) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_SERVER_WORKER_ABNORMAL_PIPE_DATA,
                         "abnormal pipeline data, msg_id=%ld, pipe_fd=%d, reactor_id=%d",
                         buffer_->info.msg_id,
                         sock->get_fd(),
                         buffer_->info.reactor_id);
        return SW_ERR;
    }
    packet_buffer->append(buffer_->data, recv_n - sizeof(buffer_->info));

    switch (prepare_packet(recv_chunk_count, packet_buffer)) {
    case SW_READY:
        return recv_n;
    case SW_CONTINUE:
        goto _read_from_pipe;
    case SW_WAIT:
        return SW_OK;
    default:
        assert(0);
        return SW_ERR;
    }
}

bool MessageBus::write(Socket *sock, SendData *resp) {
    const char *payload = resp->data;
    uint32_t l_payload = resp->info.len;
    off_t offset = 0;
    uint32_t copy_n;

    struct iovec iov[2];

    uint64_t msg_id = id_generator_();
    uint32_t max_length = buffer_size_ - sizeof(resp->info);
    resp->info.msg_id = msg_id;

    auto send_fn = [](Socket *sock, const iovec *iov, size_t iovcnt) {
        if (swoole_event_is_available()) {
            return swoole_event_writev(sock, iov, iovcnt);
        } else {
            return sock->writev_blocking(iov, iovcnt);
        }
    };

    if (l_payload == 0 || payload == nullptr) {
        resp->info.flags = 0;
        resp->info.len = 0;
        iov[0].iov_base = &resp->info;
        iov[0].iov_len = sizeof(resp->info);
        return send_fn(sock, iov, 1) == (ssize_t) iov[0].iov_len;
    }

    if (!always_chunked_transfer_ && l_payload <= max_length) {
        resp->info.flags = 0;
        resp->info.len = l_payload;
        iov[0].iov_base = &resp->info;
        iov[0].iov_len = sizeof(resp->info);
        iov[1].iov_base = (void *) payload;
        iov[1].iov_len = l_payload;

        if (send_fn(sock, iov, 2) == (ssize_t)(sizeof(resp->info) + l_payload)) {
            return true;
        }
        if (sock->catch_write_pipe_error(errno) == SW_REDUCE_SIZE && max_length > SW_BUFFER_SIZE_STD) {
            max_length = SW_IPC_BUFFER_SIZE;
        } else {
            return false;
        }
    }

    resp->info.flags = SW_EVENT_DATA_CHUNK | SW_EVENT_DATA_BEGIN;
    resp->info.len = l_payload;

    while (l_payload > 0) {
        if (l_payload > max_length) {
            copy_n = max_length;
        } else {
            resp->info.flags |= SW_EVENT_DATA_END;
            copy_n = l_payload;
        }

        iov[0].iov_base = &resp->info;
        iov[0].iov_len = sizeof(resp->info);
        iov[1].iov_base = (void *) (payload + offset);
        iov[1].iov_len = copy_n;

        swoole_trace("finish, type=%d|len=%u", resp->info.type, copy_n);

        if (send_fn(sock, iov, 2) < 0) {
            if (sock->catch_write_pipe_error(errno) == SW_REDUCE_SIZE && max_length > SW_BUFFER_SIZE_STD) {
                max_length = SW_IPC_BUFFER_SIZE;
                if (resp->info.flags & SW_EVENT_DATA_END) {
                    resp->info.flags &= ~SW_EVENT_DATA_END;
                }
                continue;
            }
            return false;
        }

        if (resp->info.flags & SW_EVENT_DATA_BEGIN) {
            resp->info.flags &= ~SW_EVENT_DATA_BEGIN;
        }

        l_payload -= copy_n;
        offset += copy_n;
    }

    return true;
}

size_t MessageBus::get_memory_size() {
    size_t size = buffer_size_;
    for (auto p : packet_pool_) {
        size += p.second->size;
    }
    return size;
}

}  // namespace swoole

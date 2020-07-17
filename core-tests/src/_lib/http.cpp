#include "tests.h"
#include "httplib_client.h"

using httplib::Client;
using httplib::WebSocketFrame;

bool Client::Push(const char *data, size_t length, int opcode) {
    if (!socket_.is_open()) {
        return false;
    }
    return process_socket(socket_, [&](Stream &strm) {
        swString buffer = {};
        char buf[32];
        buffer.size = sizeof(buf);
        buffer.str = buf;

        swWebSocket_encode(&buffer, data, length, opcode,
                           SW_WEBSOCKET_FLAG_FIN | SW_WEBSOCKET_FLAG_ENCODE_HEADER_ONLY);
        strm.write(buffer.str, buffer.length);
        strm.write(data, length);
        return true;
    });
}

std::shared_ptr<WebSocketFrame> Client::Recv() {

    auto msg = std::make_shared<WebSocketFrame>();
    auto retval = process_socket(socket_, [&](Stream &strm) {

        swProtocol proto = {};
        proto.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        proto.get_package_length = swWebSocket_get_package_length;
        proto.package_max_length = SW_INPUT_BUFFER_SIZE;

        char buf[1024];
        ssize_t packet_len;

        if (strm.read(buf, SW_WEBSOCKET_HEADER_LEN) <= 0) {
            return false;
        }
        packet_len = proto.get_package_length(&proto, nullptr, buf, 2);
        if (packet_len < 0) {
            return false;
        }
        if (packet_len == 0) {
            if (strm.read(buf + SW_WEBSOCKET_HEADER_LEN, proto.real_header_length - SW_WEBSOCKET_HEADER_LEN) <= 0) {
                return false;
            }
            packet_len = proto.get_package_length(&proto, nullptr, buf, proto.real_header_length);
            if (packet_len <= 0) {
                return false;
            }
         }

        char *data = (char *) malloc(packet_len + 1);
        if (data == nullptr) {
            return false;
        }
        data[packet_len] = 0;

        uint32_t header_len = proto.real_header_length > 0 ? proto.real_header_length : SW_WEBSOCKET_HEADER_LEN;
        memcpy(data, buf, header_len);

        ssize_t read_bytes = header_len;
        while(read_bytes < packet_len) {
            auto n_read = strm.read(data + read_bytes, packet_len - read_bytes);
            if (n_read <= 0) {
                free(data);
                return false;
            }
            read_bytes += n_read;
        }

        return swWebSocket_decode(msg.get(), data, packet_len);
    });

    return retval ? msg : nullptr;
}

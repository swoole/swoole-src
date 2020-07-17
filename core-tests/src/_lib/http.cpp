#include "tests.h"
#include "httplib_client.h"

using httplib::Client;

bool Client::Push(const std::string &data, int opcode) {
    if (!socket_.is_open()) {
        return false;
    }
    return process_socket(socket_, [&](Stream &strm) {
        swString buffer = {};
        char buf[32];
        buffer.size = sizeof(buf);
        buffer.str = buf;

        swWebSocket_encode(&buffer, data.c_str(), data.length(), opcode,
                           SW_WEBSOCKET_FLAG_FIN | SW_WEBSOCKET_FLAG_ENCODE_HEADER_ONLY);
        strm.write(buffer.str, buffer.length);
        strm.write(data.c_str(), data.length());
        return true;
    });
}

std::shared_ptr<swWebSocket_frame> Client::Recv() {

    auto msg = std::make_shared<swWebSocket_frame>();
    auto retval = process_socket(socket_, [&](Stream &strm) {

        swProtocol proto = {};
        proto.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        proto.get_package_length = swWebSocket_get_package_length;
        proto.package_max_length = SW_INPUT_BUFFER_SIZE;

        char buf[1024];
        ssize_t retval;

        if (strm.read(buf, SW_WEBSOCKET_HEADER_LEN) <= 0) {
            return false;
        }
        retval = proto.get_package_length(&proto, nullptr, buf, 2);
        if (retval < 0) {
            return false;
        }

        if (retval == 0) {
            if (strm.read(buf + SW_WEBSOCKET_HEADER_LEN, proto.real_header_length - SW_WEBSOCKET_HEADER_LEN) <= 0) {
                return false;
            }
            retval = proto.get_package_length(&proto, nullptr, buf, proto.real_header_length);
            if (retval <= 0) {
                return false;
            }
        }

        char *data = (char *) malloc(retval);
        if (data == nullptr) {
            return false;
        }

        uint32_t header_len = proto.real_header_length > 0 ? proto.real_header_length : SW_WEBSOCKET_HEADER_LEN;
        memcpy(data, buf, header_len);

        if (strm.read(data + header_len, retval - header_len) <= 0) {
            free(data);
            return false;
        }

        return swWebSocket_decode(msg.get(), data, retval);
    });

    return retval ? msg : nullptr;
}

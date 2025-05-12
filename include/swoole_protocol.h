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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "swoole_c_api.h"
#include "swoole_socket.h"

#include <netinet/tcp.h>
#include <netdb.h>

namespace swoole {

struct PacketLength {
    const char *buf;
    uint32_t buf_size;
    uint32_t header_len;
};

struct Protocol {
    typedef ssize_t (*LengthFunc)(const Protocol *, network::Socket *, PacketLength *pl);
    /* one package: eof check */
    bool split_by_eof;

    char package_eof[SW_DATA_EOF_MAXLEN];
    uint8_t package_eof_len;

    char package_length_type;
    uint8_t package_length_size;
    uint16_t package_length_offset;
    uint16_t package_body_offset;
    uint32_t package_max_length;

    void *private_data_1;
    void *private_data_2;

    /**
     * callback this function when a complete data packet is received
     */
    int (*onPackage)(const Protocol *, network::Socket *, const RecvData *);
    /**
     * parse the length value in the received data
     * @return 0: more data needs to be received
     * @return -1: abnormal value, connection should be closed
     * @return >0: the length of the data packet
     */
    LengthFunc get_package_length;
    uint8_t (*get_package_length_size)(network::Socket *);

    int recv_with_eof_protocol(network::Socket *socket, String *buffer);
    int recv_with_length_protocol(network::Socket *socket, String *buffer);
    int recv_split_by_eof(network::Socket *socket, String *buffer);

    static ssize_t default_length_func(const Protocol *protocol, network::Socket *socket, PacketLength *pl);
};
}  // namespace swoole

#ifdef __BYTE_ORDER
#define SW_BYTE_ORDER __BYTE_ORDER
#elif defined(_BYTE_ORDER)
#define SW_BYTE_ORDER _BYTE_ORDER
#elif defined(BYTE_ORDER)
#define SW_BYTE_ORDER BYTE_ORDER
#else
#error "Unable to determine machine byte order"
#endif

#ifdef __LITTLE_ENDIAN
#define SW_LITTLE_ENDIAN __LITTLE_ENDIAN
#elif defined(_LITTLE_ENDIAN)
#define SW_LITTLE_ENDIAN _LITTLE_ENDIAN
#elif defined(LITTLE_ENDIAN)
#define SW_LITTLE_ENDIAN LITTLE_ENDIAN
#else
#error "No LITTLE_ENDIAN macro"
#endif

static sw_inline uint16_t swoole_swap_endian16(uint16_t x) {
    return (((x & 0xff) << 8) | ((x & 0xff00) >> 8));
}

static sw_inline uint32_t swoole_swap_endian32(uint32_t x) {
    return (((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24));
}

static sw_inline uint64_t swoole_swap_endian64(uint64_t x) {
    return (((x & 0xff) << 56) | ((x & 0xff00) << 40) | ((x & 0xff0000) << 24) | ((x & 0xff000000) << 8) |
            ((x & 0xff00000000) >> 8) | ((x & 0xff0000000000) >> 24) | ((x & 0xff000000000000) >> 40) |
            ((x & 0xff00000000000000) >> 56));
}

int64_t swoole_unpack(char type, const void *data);
uint64_t swoole_hton64(uint64_t value);
uint64_t swoole_ntoh64(uint64_t value);

void swoole_dump_ascii(const char *data, size_t size);
void swoole_dump_bin(const char *data, char type, size_t size);
void swoole_dump_hex(const char *data, size_t outlen);

char *swoole_dec2hex(ulong_t value, int base);
ulong_t swoole_hex2dec(const char *hex, size_t *parsed_bytes);
int swoole_type_size(char type);

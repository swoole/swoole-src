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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "swoole_socket.h"

#include <netinet/tcp.h>
#include <netdb.h>

namespace swoole {

struct Protocol {
    /* one package: eof check */
    uint8_t split_by_eof;
    uint8_t package_eof_len;
    char package_eof[SW_DATA_EOF_MAXLEN];

    char package_length_type;
    uint8_t package_length_size;
    uint16_t package_length_offset;
    uint16_t package_body_offset;
    uint32_t package_max_length;

    void *private_data;
    void *private_data_2;
    uint16_t real_header_length;
    uint16_t ext_flags;

    int (*onPackage)(swProtocol *, swSocket *, const char *, uint32_t);
    ssize_t (*get_package_length)(swProtocol *, swSocket *, const char *, uint32_t);
    uint8_t (*get_package_length_size)(swSocket *);
};
}

typedef ssize_t (*swProtocol_length_function)(swProtocol *, swSocket *, const char *, uint32_t);

static sw_inline uint16_t swoole_swap_endian16(uint16_t x) {
    return (((x & 0xff) << 8) | ((x & 0xff00) >> 8));
}

static sw_inline uint32_t swoole_swap_endian32(uint32_t x) {
    return (((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24));
}

static sw_inline int32_t swoole_unpack(char type, const void *data) {
    switch (type) {
    /*-------------------------16bit-----------------------------*/
    case 'c':
        return *((int8_t *) data);
    case 'C':
        return *((uint8_t *) data);
    /*-------------------------16bit-----------------------------*/
    /**
     * signed short (always 16 bit, machine byte order)
     */
    case 's':
        return *((int16_t *) data);
    /**
     * unsigned short (always 16 bit, machine byte order)
     */
    case 'S':
        return *((uint16_t *) data);
    /**
     * unsigned short (always 16 bit, big endian byte order)
     */
    case 'n':
        return ntohs(*((uint16_t *) data));
    /**
     * unsigned short (always 32 bit, little endian byte order)
     */
    case 'v':
        return swoole_swap_endian16(ntohs(*((uint16_t *) data)));

    /*-------------------------32bit-----------------------------*/
    /**
     * unsigned long (always 32 bit, machine byte order)
     */
    case 'L':
        return *((uint32_t *) data);
    /**
     * signed long (always 32 bit, machine byte order)
     */
    case 'l':
        return *((int *) data);
    /**
     * unsigned long (always 32 bit, big endian byte order)
     */
    case 'N':
        return ntohl(*((uint32_t *) data));
    /**
     * unsigned short (always 32 bit, little endian byte order)
     */
    case 'V':
        return swoole_swap_endian32(ntohl(*((uint32_t *) data)));

    default:
        return *((uint32_t *) data);
    }
}

static sw_inline uint64_t swoole_hton64(uint64_t host) {
    uint64_t ret = 0;
    uint32_t high, low;

    low = host & 0xFFFFFFFF;
    high = (host >> 32) & 0xFFFFFFFF;
    low = htonl(low);
    high = htonl(high);

    ret = low;
    ret <<= 32;
    ret |= high;
    return ret;
}

static sw_inline uint64_t swoole_ntoh64(uint64_t net) {
    uint64_t ret = 0;
    uint32_t high, low;

    low = net & 0xFFFFFFFF;
    high = net >> 32;
    low = ntohl(low);
    high = ntohl(high);

    ret = low;
    ret <<= 32;
    ret |= high;
    return ret;
}

void swoole_dump_ascii(const char *data, size_t size);
void swoole_dump_bin(const char *data, char type, size_t size);
void swoole_dump_hex(const char *data, size_t outlen);
char *swoole_dec2hex(ulong_t value, int base);
ulong_t swoole_hex2dec(const char *hex, size_t *parsed_bytes);
int swoole_type_size(char type);

ssize_t swProtocol_get_package_length(swProtocol *protocol, swSocket *socket, const char *data, uint32_t size);
int swProtocol_recv_check_length(swProtocol *protocol, swSocket *socket, swString *buffer);
int swProtocol_recv_check_eof(swProtocol *protocol, swSocket *socket, swString *buffer);

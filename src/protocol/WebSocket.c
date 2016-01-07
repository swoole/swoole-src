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
#include "websocket.h"
#include <sys/time.h>

int swWebSocket_get_package_length(swProtocol *protocol, swConnection *conn, char *buf, uint32_t length)
{
    char mask = (buf[1] >> 7) & 0x1;
    //0-125
    uint64_t payload_length = buf[1] & 0x7f;
    int header_length = SW_WEBSOCKET_HEADER_LEN;
    buf += SW_WEBSOCKET_HEADER_LEN;

    //uint16_t, 2byte
    if (length == 0x7e)
    {
        payload_length = ntohs(*((uint16_t *) buf));
        header_length += 2;
    }
    //uint64_t, 8byte
    else if (length > 0x7e)
    {
        payload_length = swoole_ntoh64(*((uint64_t *) buf));
        header_length += 8;
    }

    if (mask)
    {
        header_length += SW_WEBSOCKET_MASK_LEN;
    }

    return header_length + payload_length;
}

//static void swWebSocket_print_frame(swWebSocket_frame *frm);

void swWebSocket_encode(swString *buffer, char *data, size_t length, char opcode, int fin, int isMask)
{
    int pos = 0;
    char frame_header[16];

    frame_header[pos++] = FRAME_SET_FIN(fin) | FRAME_SET_OPCODE(opcode);
    if (length < 126)
    {
        frame_header[pos++] = FRAME_SET_MASK(isMask) | FRAME_SET_LENGTH(length, 0);
    }
    else
    {
        if (length < 65536)
        {
            frame_header[pos++] = FRAME_SET_MASK(isMask) | 126;
        }
        else
        {
            frame_header[pos++] = FRAME_SET_MASK(isMask) | 127;
            frame_header[pos++] = FRAME_SET_LENGTH(length, 7);
            frame_header[pos++] = FRAME_SET_LENGTH(length, 6);
            frame_header[pos++] = FRAME_SET_LENGTH(length, 5);
            frame_header[pos++] = FRAME_SET_LENGTH(length, 4);
            frame_header[pos++] = FRAME_SET_LENGTH(length, 3);
            frame_header[pos++] = FRAME_SET_LENGTH(length, 2);
        }
        frame_header[pos++] = FRAME_SET_LENGTH(length, 1);
        frame_header[pos++] = FRAME_SET_LENGTH(length, 0);
    }

    if (isMask)
    {
        int i;
        char masks[SW_WEBSOCKET_MASK_LEN];
        for (i = 0; i < SW_WEBSOCKET_MASK_LEN; i++)
        {
            srand((int) time(0));
            masks[i] = (rand() % 26) + 'a';
            frame_header[pos++] = masks[i];
        }
        for (i = 0; i < length; i++)
        {
            data[i] ^= masks[i % SW_WEBSOCKET_MASK_LEN];
        }
    }
    //websocket frame header
    swString_append_ptr(buffer, frame_header, pos);
    //websocket frame body
    swString_append_ptr(buffer, data, length);
}

/*  The following is websocket data frame:
 +-+-+-+-+-------+-+-------------+-------------------------------+
 0                   1                   2                   3   |
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 |
 +-+-+-+-+-------+-+-------------+-------------------------------+
 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 | |1|2|3|       |K|             |                               |
 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 |     Extended payload length continued, if payload len == 127  |
 + - - - - - - - - - - - - - - - +-------------------------------+
 |                               |Masking-key, if MASK set to 1  |
 +-------------------------------+-------------------------------+
 | Masking-key (continued)       |          Payload Data         |
 +-------------------------------- - - - - - - - - - - - - - - - +
 :                     Payload Data continued ...                :
 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 |                     Payload Data continued ...                |
 +---------------------------------------------------------------+
 */
void swWebSocket_decode(swWebSocket_frame *frame, swString *data)
{
    memcpy(frame, data->str, SW_WEBSOCKET_HEADER_LEN);

    //0-125
    size_t payload_length = frame->header.LENGTH;
    uint8_t header_length = SW_WEBSOCKET_HEADER_LEN;
    char *buf = data->str + SW_WEBSOCKET_HEADER_LEN;

    //uint16_t, 2byte
    if (frame->header.LENGTH == 0x7e)
    {
        payload_length = ntohs(*((uint16_t *) buf));
        header_length += 2;
    }
    //uint64_t, 8byte
    else if (frame->header.LENGTH > 0x7e)
    {
        payload_length = swoole_ntoh64(*((uint64_t *) buf));
        header_length += 8;
    }

    if (frame->header.MASK)
    {
        char *mask_key = frame->mask_key;
        memcpy(mask_key, data->str + header_length, SW_WEBSOCKET_MASK_LEN);
        header_length += SW_WEBSOCKET_MASK_LEN;
        buf = data->str + header_length;
        int i;
        for (i = 0; i < payload_length; i++)
        {
            buf[i] ^= mask_key[i % SW_WEBSOCKET_MASK_LEN];
        }
    }
    frame->payload_length = payload_length;
    frame->header_length = header_length;
    frame->payload = data->str + header_length;
}

void swWebSocket_print_frame(swWebSocket_frame *frm)
{
    int i;
    printf("FIN: %x, RSV1: %d, RSV2: %d, RSV3: %d, opcode: %d, MASK: %d, length: %ld\n", frm->header.FIN,
            frm->header.RSV1, frm->header.RSV2, frm->header.RSV3, frm->header.OPCODE, frm->header.MASK,
            frm->payload_length);

    if (frm->payload_length)
    {
        printf("payload: %s = %d\n", frm->payload, strlen(frm->payload));
    }
}



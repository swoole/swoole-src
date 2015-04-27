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
#include "include/websocket.h"
#include <sys/time.h>

//static uint64_t hton64(uint64_t host);
static uint64_t ntoh64(uint64_t network);

//static void swWebSocket_print_frame(swWebSocket_frame *frm);
static void swWebSocket_unmask(char *masks, swHttpRequest *request);

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

    if(isMask) {
        int i;
        char masks[SW_WEBSOCKET_MASK_LEN];
        for(i = 0; i < SW_WEBSOCKET_MASK_LEN; i++)
        {
            srand((int)time(0));
            masks[i] = (rand()%26)+'a';
            frame_header[pos++] = masks[i];
        }
        for(i=0; i< length; i++)
        {
            data[i] ^= masks[i % SW_WEBSOCKET_MASK_LEN];
        }
    }
    //websocket frame header
    swString_append_ptr(buffer, frame_header, pos);
    //websocket frame body
    swString_append_ptr(buffer, data, length);
}

//uint64_t hton64(uint64_t host)
//{
//  uint64_t ret = 0;
//  uint32_t high, low;
//
//  low = host & 0xFFFFFFFF;
//  high = (host >> 32) & 0xFFFFFFFF;
//  low = htonl(low);
//  high = htonl(high);
//  ret = low;
//  ret <<= 32;
//  ret |= high;
//  return ret;
//}

uint64_t ntoh64(uint64_t host)
{
    uint64_t ret = 0;
    uint32_t high, low;

    low = host & 0xFFFFFFFF;
    high = (host >> 32) & 0xFFFFFFFF;
    low = ntohl(low);
    high = ntohl(high);
    ret = low;
    ret <<= 32;
    ret |= high;
    return ret;
}

int swWebSocket_isEof(char *buf)
{
    return (buf[0] >> 7) & 0x1;
}

/*  The following is websocket data frame:

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
int swWebSocket_decode(swHttpRequest *request)
{
    char *buf = request->buffer->str;
    char fin = (buf[0] >> 7) & 0x1;
    char rsv1 = (buf[0] >> 6) & 0x1;
    char rsv2 = (buf[0] >> 5) & 0x1;
    char rsv3 = (buf[0] >> 4) & 0x1;
    char opcode = buf[0] & 0xf;
    char mask = (buf[1] >> 7) & 0x1;

    if (0x0 != rsv1 || 0x0 != rsv2 || 0x0 != rsv3)
    {
        swTrace("rsv error %d %d %d\n", rsv1, rsv2, rsv3);
        request->free_memory = SW_WAIT;
        return SW_ERR;
    }
    request->opcode = opcode;
    request->free_memory = 0;

    //0-125
    char length = buf[1] & 0x7f;
    buf += SW_WEBSOCKET_HEADER_LEN;
    request->buffer->offset += SW_WEBSOCKET_HEADER_LEN;
    /**
    * 126
    */
    if (length < 0x7E)
    {
        request->content_length = length;
    }
        /**
        * Short
        */
    else if (0x7E == length)
    {
        request->content_length = ntohs(*((uint16_t *) buf));
        request->buffer->offset += sizeof(short);
    }
    else
    {
        request->content_length = ntoh64(*((uint64_t *) buf));
        request->buffer->offset += sizeof(int64_t);
    }

    if (request->content_length + request->buffer->offset > request->buffer->length)
    {
        request->free_memory = SW_WAIT;
        return SW_OK;
    }

    if (mask)
    {
        char masks[SW_WEBSOCKET_MASK_LEN];
        memcpy(masks, (request->buffer->str + request->buffer->offset), SW_WEBSOCKET_MASK_LEN);
        request->buffer->offset += SW_WEBSOCKET_MASK_LEN;

        if (request->content_length)
        {
            swWebSocket_unmask(masks, request);
        }
    }

    //swTrace("offset: %d\n", request->buffer->offset);
    request->buffer->offset--;
    request->buffer->str[request->buffer->offset] = opcode;
    request->buffer->offset--;
    request->buffer->str[request->buffer->offset] = fin;
    request->content_length += 2;
    request->buffer->str += request->buffer->offset;
    request->header_length += (request->content_length + request->buffer->offset);

    //swTrace("decode end %d %d %d====\n", request->buffer->offset, opcode, fin);

    return SW_OK;
}

int swWebSocket_decode_frame(char *buf, swString *str, int n)
{
    char fin = (buf[0] >> 7) & 0x1;
    char rsv1 = (buf[0] >> 6) & 0x1;
    char rsv2 = (buf[0] >> 5) & 0x1;
    char rsv3 = (buf[0] >> 4) & 0x1;
    char opcode = buf[0] & 0xf;
    char mask = (buf[1] >> 7) & 0x1;


    if (0x0 != rsv1 || 0x0 != rsv2 || 0x0 != rsv3)
    {
        swTrace("rsv error %d %d %d\n", rsv1, rsv2, rsv3);
        return SW_ERR;
    }

    int offset = 0;

    //0-125
    char length = buf[1] & 0x7f;
    swTrace("frame length: %d offset: %d\n", length, offset);
//    buf += SW_WEBSOCKET_HEADER_LEN;
    offset += SW_WEBSOCKET_HEADER_LEN;
    /**
    * 126
    */
    if (length < 0x7E)
    {
        str->length = length;
    }
        /**
        * Short
        */
    else if (0x7E == length)
    {
        buf += SW_WEBSOCKET_HEADER_LEN;
        str->length = ntohs(*((uint16_t *) buf));
        offset += sizeof(short);
        buf -= SW_WEBSOCKET_HEADER_LEN;
    }
    else
    {
        buf += SW_WEBSOCKET_HEADER_LEN;
        str->length = ntoh64(*((uint64_t *) buf));
        offset += sizeof(int64_t);
        buf -= SW_WEBSOCKET_HEADER_LEN;
    }



    if (mask)
    {
        char masks[SW_WEBSOCKET_MASK_LEN];
        memcpy(masks, (buf + offset), SW_WEBSOCKET_MASK_LEN);
//        swTrace("masks %s\n", masks);
        offset += SW_WEBSOCKET_MASK_LEN;

        str->size = str->length + offset;

        if(str->size > n) {
            //swTrace("frame length: %d offset: %d\n", str->length, offset);
            return SW_OK;
        }

        if (str->length)
        {
            int i;
            for (i = 0; i < str->length; i++)
            {
//                swTrace("unmask i:%d %c %c \n", i, buf[i + offset], masks[i % SW_WEBSOCKET_MASK_LEN]);
                buf[i + offset] ^= masks[i % SW_WEBSOCKET_MASK_LEN];
//                swTrace("unmask i:%d %c\n", i, buf[i + offset]);
            }
        }
    }
    else
    {
        str->size = str->length + offset;

        if(str->size > n) {
            //swTrace("frame length: %d offset: %d\n", str->length, offset);
            return SW_OK;
        }
    }

    //swTrace("offset: %d lenght:%d opcode: %d, fin: %d\n", offset, str->length, opcode, fin);
    offset--;
    buf[offset] = opcode;
    offset--;
    buf[offset] = fin;
    str->length += 2;
    buf += offset;
    str->offset = offset;
//    str->size = str->length + str->offset;
    str->str = buf;
    return SW_OK;
}


static void swWebSocket_unmask(char *masks, swHttpRequest *request)
{
    int i;
    for (i = 0; i < request->content_length; i++)
    {
        //                swTrace("unmask i:%d %c\n", i, request->buffer->str[i]);
        request->buffer->str[i + request->buffer->offset] ^= masks[i % SW_WEBSOCKET_MASK_LEN];
        //                swTrace("unmask i:%d %c\n", i, request->buffer->str[i]);
    }
}


//static void swWebSocket_print_frame(swWebSocket_frame *frm)
//{
//  int i;
//  printf("FIN: %x, RSV1: %d, RSV2: %d, RSV3: %d, opcode: %d, MASK: %d, length: %ld\n", frm->header.FIN,
//          frm->header.RSV1, frm->header.RSV2, frm->header.RSV3, frm->header.OPCODE, frm->header.MASK,
//          frm->length);
//
//  if (frm->length)
//  {
//      printf("payload: %s = %d\n", frm->payload, strlen(frm->payload));
//  }
//
//



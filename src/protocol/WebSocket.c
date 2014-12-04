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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include <include/websocket.h>


static uint64_t hton64(uint64_t host);
static uint64_t ntoh64(uint64_t network);

//static void swWebSocket_print_frame(swWebSocket_frame *frm);
static void swWebSocket_unmask(char *masks, swHttpRequest *request);

swString *swWebSocket_encode(swString *data)
{
    swString *buf = swString_new(data->length+16);
    int pos = 0;
    buf->str[pos++] = FRAME_SET_FIN(1) | FRAME_SET_OPCODE(0x1);
    if (data->length < 126) {
        buf->str[pos++] =
                FRAME_SET_MASK(0) | FRAME_SET_LENGTH(data->length, 0);
    }
    else {
        if (data->length < 65536) {
            buf->str[pos++] = FRAME_SET_MASK(0) | 126;
        }
        else {
            buf->str[pos++] = FRAME_SET_MASK(0) | 127;
            buf->str[pos++] = FRAME_SET_LENGTH(data->length, 7);
            buf->str[pos++] = FRAME_SET_LENGTH(data->length, 6);
            buf->str[pos++] = FRAME_SET_LENGTH(data->length, 5);
            buf->str[pos++] = FRAME_SET_LENGTH(data->length, 4);
            buf->str[pos++] = FRAME_SET_LENGTH(data->length, 3);
            buf->str[pos++] = FRAME_SET_LENGTH(data->length, 2);
        }
        buf->str[pos++] = FRAME_SET_LENGTH(data->length, 1);
        buf->str[pos++] = FRAME_SET_LENGTH(data->length, 0);
    }
    buf->length = pos;
    swString_append(buf, data);
	return buf;
}

uint64_t hton64(uint64_t host)
{
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

int swWebSocket_isEof(char * buf)
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
    char fin    = (buf[0] >> 7) & 0x1;
    char rsv1   = (buf[0] >> 6) & 0x1;
    char rsv2   = (buf[0] >> 5) & 0x1;
    char rsv3   = (buf[0] >> 4) & 0x1;
    char opcode =  buf[0]       & 0xf;
    char mask   = (buf[1] >> 7) & 0x1;
    
    if(0x0 != rsv1 || 0x0 != rsv2 || 0x0 != rsv3)
    {
        return SW_ERR;
    }
    request->opcode = opcode;
    if(fin) {
        request->state = 0;
    }else{   //等待完整包
        request->state = SW_WAIT;
    }
    
        //0-125
    char length =  buf[1]       & 0x7f;
    buf+=SW_WEBSOCKET_HEADER_LEN;
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
    
    if (mask && request->state == 0)
    {
        char masks[SW_WEBSOCKET_MASK_LEN];
        memcpy(masks, (request->buffer->str + request->buffer->offset), SW_WEBSOCKET_MASK_LEN);
        request->buffer->offset += SW_WEBSOCKET_MASK_LEN;

        if (request->content_length)
        {
            swWebSocket_unmask(masks, request);
        }
    }
    
    request->buffer->str +=request->buffer->offset;
    
    swTrace("decode end\n");

    return SW_OK;
}

static void swWebSocket_unmask(char *masks, swHttpRequest *request)
{
	int i;
	for (i =0  ; i < request->content_length; i++)
	{
//                swTrace("unmask i:%d %c\n", i, request->buffer->str[i]);
		request->buffer->str[i+request->buffer->offset]  ^=  masks[i % SW_WEBSOCKET_MASK_LEN];
//                swTrace("unmask i:%d %c\n", i, request->buffer->str[i]);
	}
}

swString *swWebSocket_handShake(char *key)
{

}

//static void swWebSocket_print_frame(swWebSocket_frame *frm)
//{
//	int i;
//	printf("FIN: %x, RSV1: %d, RSV2: %d, RSV3: %d, opcode: %d, MASK: %d, length: %ld\n", frm->header.FIN,
//			frm->header.RSV1, frm->header.RSV2, frm->header.RSV3, frm->header.OPCODE, frm->header.MASK,
//			frm->length);
//
//	if (frm->length)
//	{
//		printf("payload: %s = %d\n", frm->payload, strlen(frm->payload));
//	}
//
//}


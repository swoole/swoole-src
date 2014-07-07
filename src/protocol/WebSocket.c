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

#define SW_WEBSOCKET_HEADER_LEN  2
#define SW_WEBSOCKET_MASK_LEN    4
#define SW_WEBSOCKET_EXT16_LENGTH 0x7E
#define SW_WEBSOCKET_EXT16_MAX_LEN 0xFFFF
#define SW_WEBSOCKET_EXT64_LENGTH 0x7F
#define SW_WEBSOCKET_MASKED(frm) (frm->header.MASK)

#define SW_WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef struct
{
	/**
	 * fin:1 rsv1:1 rsv2:1 rsv3:1 opcode:4
	 */
	struct
	{
		unsigned char OPCODE :4;
		unsigned char RSV3 :1;
		unsigned char RSV2 :1;
		unsigned char RSV1 :1;
		unsigned char FIN :1;
		unsigned char LENGTH :7;
		unsigned char MASK :1;
	} header;
	char mask[SW_WEBSOCKET_MASK_LEN];
	size_t length;
	char *payload;

} swWebSocket_frame;


enum
{
	WEBSOCKET_OPCODE_CONTINUATION_FRAME = 0x0,
	WEBSOCKET_OPCODE_TEXT_FRAME = 0x1,
	WEBSOCKET_OPCODE_BINARY_FRAME = 0x2,
	WEBSOCKET_OPCODE_CONNECTION_CLOSE = 0x8,
	WEBSOCKET_OPCODE_PING = 0x9,
	WEBSOCKET_OPCODE_PONG = 0xa,

	WEBSOCKET_CLOSE_NORMAL = 1000,
	WEBSOCKET_CLOSE_GOING_AWAY = 1001,
	WEBSOCKET_CLOSE_PROTOCOL_ERROR = 1002,
	WEBSOCKET_CLOSE_DATA_ERROR = 1003,
	WEBSOCKET_CLOSE_STATUS_ERROR = 1005,
	WEBSOCKET_CLOSE_ABNORMAL = 1006,
	WEBSOCKET_CLOSE_MESSAGE_ERROR = 1007,
	WEBSOCKET_CLOSE_POLICY_ERROR = 1008,
	WEBSOCKET_CLOSE_MESSAGE_TOO_BIG = 1009,
	WEBSOCKET_CLOSE_EXTENSION_MISSING = 1010,
	WEBSOCKET_CLOSE_SERVER_ERROR = 1011,
	WEBSOCKET_CLOSE_TLS = 1015,
	WEBSOCKET_VERSION = 13,

} SW_WEBSOCKET;

uint64_t hton64(uint64_t host);
uint64_t ntoh64(uint64_t network);

static void swWebSocket_print_frame(swWebSocket_frame *frm);
static void swWebSocket_unmask(swWebSocket_frame *frm);

int swWebSocket_encode(char *data, int length)
{
	return SW_OK;
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

int swWebSocket_decode(char *buf, int length)
{
	swWebSocket_frame *frm = malloc(sizeof(swWebSocket_frame));
	bzero(frm, sizeof(swWebSocket_frame));

	memcpy(frm, buf, 2);
	buf += SW_WEBSOCKET_HEADER_LEN;

	/**
	 * 126
	 */
	if (frm->header.LENGTH < 0x7E)
	{
		frm->length = frm->header.LENGTH;
	}
	/**
	 * Short
	 */
	else if (0x7E == frm->header.LENGTH)
	{
		frm->length = ntohs(*((uint16_t *) buf));
		buf += sizeof(short);
	}
	else
	{
		frm->length = ntoh64(*((uint64_t *) buf));
		buf += sizeof(int64_t);
	}

	if (frm->header.MASK)
	{
		memcpy(frm->mask, buf, SW_WEBSOCKET_MASK_LEN);
		buf += SW_WEBSOCKET_MASK_LEN;
		frm->payload = buf;

		if (frm->length)
		{
			swWebSocket_unmask(frm);
		}
	}
	else
	{
		frm->payload = buf;
	}
	swWebSocket_print_frame(frm);

	return SW_OK;
}

static void swWebSocket_unmask(swWebSocket_frame *frm)
{
	int i;
	for (i = 0; i < frm->length; i++)
	{
		frm->payload[i] = frm->payload[i] ^ frm->mask[i % SW_WEBSOCKET_MASK_LEN];
	}
}

static void swWebSocket_print_frame(swWebSocket_frame *frm)
{
	int i;
	printf("FIN: %x, RSV1: %d, RSV2: %d, RSV3: %d, opcode: %d, MASK: %d, length: %ld\n", frm->header.FIN,
			frm->header.RSV1, frm->header.RSV2, frm->header.RSV3, frm->header.OPCODE, frm->header.MASK,
			frm->length);

	if (frm->length)
	{
		printf("payload: %s\n", frm->payload);
	}
}


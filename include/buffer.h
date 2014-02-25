/*
 * buffer.h
 *
 *  Created on: 2013-6-4
 *      Author: htf
 */

#ifndef SW_BUFFER_H_
#define SW_BUFFER_H_

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _swDataBuffer_trunk
{
	char *data;
	uint32_t len;
	struct _swDataBuffer_trunk *next;
} swDataBuffer_trunk;

typedef struct _swDataBuffer_item
{
	int fd;
	uint8_t trunk_num; //trunk数量
	uint32_t length;
	swDataBuffer_trunk *head;
	swDataBuffer_trunk *tail;
} swDataBuffer_item;

typedef struct _swDataBuffer
{
	swHashMap map;
	uint16_t trunk_size;
	uint16_t max_length; //最大数据量
} swDataBuffer;

#define swDataBuffer_getTrunk(data_buffer, item)   (item->tail)

swDataBuffer_item* swDataBuffer_newItem(swDataBuffer *data_buffer, int fd, int trunk_size);
swDataBuffer_trunk *swDataBuffer_newTrunk(swDataBuffer *data_buffer, swDataBuffer_item *item);
swDataBuffer_item *swDataBuffer_getItem(swDataBuffer *data_buffer, int fd);
int swDataBuffer_clear(swDataBuffer *data_buffer, int fd);
void swDataBuffer_debug(swDataBuffer *data_buffer, swDataBuffer_item *item);
int swDataBuffer_flush(swDataBuffer *data_buffer, swDataBuffer_item *item);

#ifdef __cplusplus
}
#endif

#endif /* SW_BUFFER_H_ */

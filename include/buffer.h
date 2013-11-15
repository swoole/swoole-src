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
	uint16_t len;
	struct _swDataBuffer_trunk *pre;
	struct _swDataBuffer_trunk *next;
} swDataBuffer_trunk;

typedef struct _swDataBuffer_item
{
	int fd;
	uint8_t trunk_num;
	swDataBuffer_trunk *first;
	swDataBuffer_trunk *last;
} swDataBuffer_item;

typedef struct _swDataBuffer
{
	swHashMap map;
	uint16_t trunk_size;
	uint8_t max_trunk;
} swDataBuffer;

swDataBuffer_item* swDataBuffer_newItem(swDataBuffer *data_buffer, int fd, int trunk_size);
swDataBuffer_trunk *swDataBuffer_newTrunk(swDataBuffer *data_buffer, swDataBuffer_item *item);
swDataBuffer_item *swDataBuffer_getItem(swDataBuffer *data_buffer, int fd);
swDataBuffer_trunk *swDataBuffer_getTrunk(swDataBuffer *data_buffer, swDataBuffer_item *item);
int swDataBuffer_clear(swDataBuffer *data_buffer, int fd);
void swDataBuffer_append(swDataBuffer *data_buffer, swDataBuffer_item *item, swDataBuffer_trunk *trunk);
void swDataBuffer_debug(swDataBuffer *data_buffer, swDataBuffer_item *item);
int swDataBuffer_flush(swDataBuffer *data_buffer, swDataBuffer_item *item);

#ifdef __cplusplus
}
#endif

#endif /* SW_BUFFER_H_ */

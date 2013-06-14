/*
 * buffer.h
 *
 *  Created on: 2013-6-4
 *      Author: htf
 */

#ifndef SW_BUFFER_H_
#define SW_BUFFER_H_

typedef struct _swDataBuffer_item
{
	int fd;
	uint16_t len;
	char *buf;
	UT_hash_handle hh;
} swDataBuffer_item;

typedef struct _swDataBuffer
{
	swDataBuffer_item *ht;
} swDataBuffer;


SWINLINE swDataBuffer_item* swDataBuffer_create(swDataBuffer *data_buffer, int fd, int buffer_size);
SWINLINE int swDataBuffer_flush(swDataBuffer *data_buffer, int fd);
SWINLINE void swDataBuffer_append(swDataBuffer_item *item, char *new_data, int len);
SWINLINE swDataBuffer_item *swDataBuffer_get(swDataBuffer *data_buffer, int fd);

#endif /* SW_BUFFER_H_ */

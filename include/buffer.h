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

typedef struct _swBuffer_trunk
{
	void *data;
	uint32_t type;
	uint32_t length;
	uint16_t offset;
	struct _swBuffer_trunk *next;
} swBuffer_trunk;

typedef struct _swBuffer
{
	int fd;
	uint8_t trunk_num; //trunk数量
	uint16_t trunk_size;
	uint32_t length;
	swBuffer_trunk *head;
	swBuffer_trunk *tail;
} swBuffer;

#define swBuffer_get_trunk(buffer)   (buffer->head)
#define swBuffer_empty(buffer)       (buffer == NULL || buffer->head == NULL)

SWINLINE swBuffer* swBuffer_new(int trunk_size);
swBuffer_trunk *swBuffer_new_trunk(swBuffer *buffer, uint32_t type, uint16_t size);
SWINLINE void swBuffer_pop_trunk(swBuffer *buffer, swBuffer_trunk *trunk);
int swBuffer_in(swBuffer *buffer, swSendData *send_data);

void swBuffer_debug(swBuffer *buffer);
int swBuffer_free(swBuffer *buffer);

#ifdef __cplusplus
}
#endif

#endif /* SW_BUFFER_H_ */

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
#include "Server.h"

/**
 * create new buffer
 */
swBuffer* swBuffer_new(int trunk_size)
{
	swBuffer *buffer = sw_malloc(sizeof(swBuffer));
	if (buffer == NULL)
	{
		swWarn("malloc for buffer failed. Error: %s[%d]", strerror(errno), errno);
		return NULL;
	}

	bzero(buffer, sizeof(swBuffer));
	buffer->trunk_size = trunk_size;

	return buffer;
}

/**
 * create new trunk
 */
swBuffer_trunk *swBuffer_new_trunk(swBuffer *buffer, uint32_t type)
{
	swBuffer_trunk *trunk = sw_malloc(sizeof(swBuffer_trunk));
	if (trunk == NULL)
	{
		swWarn("malloc for trunk failed. Error: %s[%d]", strerror(errno), errno);
		return NULL;
	}

	bzero(trunk, sizeof(swBuffer_trunk));
	/**
	 * [type=SW_TRUNK_DATA] will alloc memory
	 */
	if (type == 0)
	{
		void *buf = sw_malloc(buffer->trunk_size);
		if (buf == NULL)
		{
			swWarn("malloc for data failed. Error: %s[%d]", strerror(errno), errno);
			sw_free(trunk);
			return NULL;
		}
		trunk->data = buf;
	}

	trunk->type = type;
	buffer->trunk_num++;

	if(buffer->head == NULL)
	{
		buffer->tail = buffer->head = trunk;
	}
	else
	{
		buffer->tail->next = trunk;
		buffer->tail = trunk;
	}
	return trunk;
}

/**
 * pop the head trunk
 */
SWINLINE void swBuffer_pop_trunk(swBuffer *buffer, swBuffer_trunk *trunk)
{
	//only one trunk
	if (trunk->next == NULL)
	{
		buffer->head = NULL;
		buffer->tail = NULL;
		buffer->trunk_num = 0;
	}
	else
	{
		buffer->head = trunk->next;
		buffer->trunk_num --;
	}
	if (trunk->type == SW_TRUNK_DATA)
	{
		sw_free(trunk->data);
	}
	sw_free(trunk);
}

/**
 * free buffer
 */
int swBuffer_free(swBuffer *buffer)
{
	swBuffer_trunk *trunk = buffer->head;
	swBuffer_trunk *will_free_trunk; //free the point
	while (trunk != NULL)
	{
		if (trunk->type == SW_TRUNK_DATA)
		{
			sw_free(trunk->data);
		}
		will_free_trunk = trunk;
		trunk = trunk->next;
		sw_free(will_free_trunk);
	}
	sw_free(buffer);
	return SW_OK;
}

/**
 * append to buffer queue
 */
int swBuffer_in(swBuffer *buffer, swSendData *send_data)
{
	int buf_size, copy_n;
	swBuffer_trunk *trunk = buffer->tail;
	buf_size = buffer->trunk_size - trunk->length;

	do
	{
		trunk = buffer->tail;
		copy_n =  (buf_size >= send_data->info.len) ? send_data->info.len : buf_size;
		memcpy(trunk->data, send_data->data, copy_n);
		send_data->data += copy_n;
		send_data->info.len -= copy_n;
		trunk->length += copy_n;
		buf_size += copy_n;

		//printf("trunk_n=%d|trunk=%p\n", buffer->trunk_num, trunk);

		//trunk is full, create new trunk
		if (trunk->length == buffer->trunk_size)
		{
			//trunk no enough space, creating a new trunk
			trunk = swBuffer_new_trunk(buffer, SW_TRUNK_DATA);
			if (trunk == NULL)
			{
				swWarn("append to buffer failed.");
				return SW_ERR;
			}
			buf_size = buffer->trunk_size;
		}
	}
	while(send_data->info.len > 0);

	return SW_OK;
}

/**
 * print buffer
 */
void swBuffer_debug(swBuffer *buffer)
{
	int i = 0;
	swBuffer_trunk *trunk = buffer->head;
	printf("%s\n%s\n", SW_START_LINE, __func__);
	while (trunk != NULL && trunk->next != NULL)
	{
		i++;
		printf("%d.\tlen=%d\tdata=%s\n", i, trunk->length, (char *)trunk->data);
		trunk = trunk->next;
	}
	printf("%s\n%s\n", SW_END_LINE, __func__);
}

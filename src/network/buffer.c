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

swConnBuffer* swConnection_get_buffer(swConnection *conn)
{
	swConnBuffer *buffer = conn->buffer;
	if (buffer == NULL)
	{
		buffer = sw_malloc(sizeof(swConnBuffer));
		bzero(&(buffer->data.info), sizeof(swDataHead));
		if (buffer == NULL)
		{
			swWarn("malloc fail\n");
			return NULL;
		}
		conn->buffer = buffer;
		buffer->next = NULL;
	}
	else
	{
		while (buffer->next != NULL)
		{
			buffer = buffer->next;
		}
	}
	return buffer;
}

void swConnection_clear_buffer(swConnection *conn)
{
	swConnBuffer *buffer = conn->buffer;
	while (buffer != NULL)
	{
		sw_free(buffer);
		buffer = buffer->next;
	}
	conn->buffer = NULL;
}

swDataBuffer_item* swDataBuffer_newItem(swDataBuffer *data_buffer, int fd, int trunk_size)
{
	swDataBuffer_item *newItem = sw_malloc(sizeof(swDataBuffer_item));
	//内存分配失败
	if (newItem == NULL)
	{
		swWarn("malloc for newItem failed. Error: %s[%d]", strerror(errno), errno);
		return NULL;
	}

	bzero(newItem, sizeof(swDataBuffer_item));

	//创建item时，自动建立一个trunk
	swDataBuffer_trunk *newTrunk = swDataBuffer_newTrunk(data_buffer, newItem);
	if (newTrunk == NULL)
	{
		sw_free(newItem);
		swWarn("malloc for newTrunk failed. Error: %s[%d]", strerror(errno), errno);
		return NULL;
	}

	newItem->fd = fd;
	swHashMap_add_int(&data_buffer->map, fd, newItem);

	return newItem;
}

swDataBuffer_trunk * swDataBuffer_newTrunk(swDataBuffer *data_buffer, swDataBuffer_item *item)
{
	swDataBuffer_trunk *trunk = sw_malloc(sizeof(swDataBuffer_trunk));
	if (trunk == NULL)
	{
		swWarn("malloc for trunk failed. Error: %s[%d]", strerror(errno), errno);
		return NULL;
	}
	char *buf = sw_malloc(data_buffer->trunk_size);
	if (buf == NULL)
	{
		swWarn("malloc for data failed. Error: %s[%d]", strerror(errno), errno);
		sw_free(trunk);
		return NULL;
	}
	bzero(trunk, sizeof(swDataBuffer_trunk));
	trunk->data = buf;
	item->trunk_num++;

	if(item->head == NULL)
	{
		item->tail = item->head = trunk;
	}
	else
	{
		item->tail->next = trunk;
		item->tail = trunk;
	}
	return trunk;
}

swDataBuffer_item *swDataBuffer_getItem(swDataBuffer *data_buffer, int fd)
{
	swDataBuffer_item *item = swHashMap_find_int(&data_buffer->map, fd);
	if(item == NULL)
	{
		item = swDataBuffer_newItem(data_buffer, fd, data_buffer->trunk_size);
	}
	return item;
}

int swDataBuffer_flush(swDataBuffer *data_buffer, swDataBuffer_item *item)
{
	if(item->head == NULL)
	{
		return SW_ERR;
	}
	item->head->len = 0;
	item->tail = item->head;
	item->trunk_num = 1;

	swDataBuffer_trunk *trunk = item->head->next;
	swDataBuffer_trunk *will_free_trunk; //保存trunk的指针，用于释放内存

	while (trunk!= NULL)
	{
		trunk->len = 0;
		sw_free(trunk->data);
		will_free_trunk = trunk;
		trunk = trunk->next;    //这里会指向下个指针，所以需要保存
		sw_free(will_free_trunk);
//		swWarn("will_free_trunk");
	}
	item->head->next = NULL;
	return SW_OK;
}

int swDataBuffer_clear(swDataBuffer *data_buffer, int fd)
{
	swDataBuffer_item *item = NULL;
	swHashMap_add_int(&data_buffer->map, fd, item);
	if (item == NULL)
	{
		swTrace("buffer item not found\n");
		return SW_ERR;
	}
	else
	{
		swDataBuffer_trunk *trunk = item->head;
		swDataBuffer_trunk *will_free_trunk; //保存trunk的指针，用于释放内存
		while (trunk != NULL)
		{
			sw_free(trunk->data);
			will_free_trunk = trunk;
			trunk = trunk->next;
			sw_free(will_free_trunk);
		}
		swHashMap_del_int(&data_buffer->map, fd);
		sw_free(item);
	}
	return SW_OK;
}

void swDataBuffer_debug(swDataBuffer *data_buffer, swDataBuffer_item *item)
{
	int i = 0;
	swDataBuffer_trunk *trunk = item->head;
	printf("%s\n%s\n", SW_START_LINE, __func__);
	while (trunk != NULL && trunk->next != NULL)
	{
		i++;
		printf("%d.\tlen=%d\tdata=%s\n", i, trunk->len, trunk->data);
		trunk = trunk->next;
	}
	printf("%s\n%s\n", SW_END_LINE, __func__);
}

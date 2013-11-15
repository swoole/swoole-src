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
	//创建item时，自动建立一个trunk
	swDataBuffer_trunk *newTrunk = swDataBuffer_newTrunk(data_buffer, newItem);
	if (newItem == NULL)
	{
		return NULL;
	}
	else if (newTrunk == NULL)
	{
		sw_free(newItem);
		return NULL;
	}
	else
	{
		bzero(newItem, sizeof(swDataBuffer_item));
		newItem->fd = fd;
		swHashMap_add_int(&data_buffer->map, fd, newItem);
		newItem->first = newTrunk;
		return newItem;
	}
	return NULL;
}

swDataBuffer_trunk * swDataBuffer_newTrunk(swDataBuffer *data_buffer, swDataBuffer_item *item)
{
	swDataBuffer_trunk *trunk = sw_malloc(sizeof(swDataBuffer_trunk));
	if (trunk == NULL)
	{
		return NULL;
	}
	char *buf = sw_malloc(data_buffer->trunk_size);
	if (buf == NULL)
	{
		sw_free(trunk);
		return NULL;
	}
	bzero(trunk, sizeof(swDataBuffer_trunk));
	item->trunk_num++;
	trunk->data = buf;
	return trunk;
}

swDataBuffer_item *swDataBuffer_getItem(swDataBuffer *data_buffer, int fd)
{
	swDataBuffer_item *item = NULL;
	swHashMap_add_int(&data_buffer->map, fd, item);
	return item;
}

swDataBuffer_trunk *swDataBuffer_getTrunk(swDataBuffer *data_buffer, swDataBuffer_item *item)
{
	//第一次使用
	if (item->last == NULL)
	{
		item->last = item->first;
		//printf("1.-------------------------last=%p|first=%p\n", item->last, item->first);
		return item->first;
	}
	//当前的trunk为空，可直接使用
	else if (item->last->len == 0)
	{
		//printf("3.-------------------------\n");
		return item->last;
	}
	//当前trunk
	else
	{
		//printf("2.-------------------------\n");
		swDataBuffer_trunk *trunk = swDataBuffer_newTrunk(data_buffer, item);
		if (trunk == NULL)
		{
			swWarn("dataBufer: create trunk fail\n");
			return NULL;
		}
		item->last->next = trunk;
		trunk->pre = item->last;
		item->last = trunk;
		return trunk;
	}
}

int swDataBuffer_flush(swDataBuffer *data_buffer, swDataBuffer_item *item)
{
	if(item->first == NULL)
	{
		return SW_ERR;
	}
	item->first->len = 0;
	item->last = NULL;
	item->trunk_num = 1;

	swDataBuffer_trunk *trunk = item->first->next;
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
	item->first->next = NULL;
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
		swDataBuffer_trunk *trunk = item->first;
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

void swDataBuffer_append(swDataBuffer *data_buffer, swDataBuffer_item *item, swDataBuffer_trunk *trunk)
{
	if (trunk->pre != NULL && (data_buffer->trunk_size - trunk->pre->len) > trunk->len)
	{
		//printf("merge before. pre_data=%s|pre_len=%d|cur_data=%s|cur_len=%d\n", trunk->pre->data, trunk->pre->len,
		//		trunk->data, trunk->len);

		memcpy(trunk->pre->data + trunk->pre->len, trunk->data, trunk->len);
		trunk->pre->len += trunk->len;
		trunk->len = 0;
		//printf("merge after. pre_data=%s|pre_len=%d\n", trunk->pre->data, trunk->pre->len);
	}
}

void swDataBuffer_debug(swDataBuffer *data_buffer, swDataBuffer_item *item)
{
	int i = 0;
	swDataBuffer_trunk *trunk = item->first;
	printf("%s\n%s\n", SW_START_LINE, __func__);
	while (trunk != NULL && trunk->next != NULL)
	{
		i++;
		printf("%d.\tlen=%d\tdata=%s\n", i, trunk->len, trunk->data);
		trunk = trunk->next;
	}
	printf("%s\n%s\n", SW_END_LINE, __func__);
}

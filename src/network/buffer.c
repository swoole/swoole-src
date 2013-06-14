#include "swoole.h"
#include "buffer.h"

SWINLINE swDataBuffer_item* swDataBuffer_create(swDataBuffer *data_buffer, int fd, int buffer_size)
{
	swDataBuffer_item *newItem = sw_malloc(sizeof(swDataBuffer_item));
	if (newItem == NULL)
	{
		return NULL;
	}
	else
	{
		bzero(newItem, sizeof(swDataBuffer_item));
		newItem->buf = sw_malloc(buffer_size);
		if (newItem->buf == NULL)
		{
			return NULL;
		}
		HASH_ADD_INT(data_buffer->ht, fd, newItem);
		return newItem;
	}
}

SWINLINE swDataBuffer_item *swDataBuffer_get(swDataBuffer *data_buffer, int fd)
{
	swDataBuffer_item *item;
	HASH_FIND_INT(data_buffer->ht, &fd, item);
	return item;
}

int swDataBuffer_flush(swDataBuffer *data_buffer, int fd)
{
	swDataBuffer_item *item = NULL;
	HASH_FIND_INT(data_buffer->ht, &fd, item);
	if(item == NULL)
	{
		swWarn("buffer no found.fd=%d\n", fd);
		return SW_ERR;
	}
	else
	{
		sw_free(item->buf);
		HASH_DEL(data_buffer->ht, item);
		sw_free(item);
	}
	return SW_OK;
}

void swDataBuffer_append(swDataBuffer_item *item, char *new_data, int len)
{
	memcpy(item->buf,new_data,len);
	item->buf+=len;
	item->len+=len;
}

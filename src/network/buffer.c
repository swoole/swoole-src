#include "swoole.h"
#include "Server.h"

swDataBuffer* swConnection_get_buffer(swConnection *conn)
{
	swDataBuffer *buffer = conn->buffer;
	if (buffer == NULL)
	{
		buffer = sw_malloc(sizeof(swDataBuffer));
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
	swDataBuffer *buffer = conn->buffer;
	while (buffer != NULL)
	{
		sw_free(buffer);
		buffer = buffer->next;
	}
}

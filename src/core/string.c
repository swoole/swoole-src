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

swString *swString_new(size_t size)
{
	swString *str = sw_malloc(sizeof(swString));
	if (str == NULL)
	{
		swWarn("malloc[1] failed.");
		return NULL;
	}
	bzero(str, sizeof(swString));
	str->size = size;
	str->str = sw_malloc(size);
	if (str->str == NULL)
	{
		swWarn("malloc[2] failed.");
		sw_free(str);
		return NULL;
	}
	return str;
}

void swString_free(swString *str)
{
	sw_free(str->str);
	sw_free(str);
}

int swString_append(swString *str, swString *append_str)
{
	int new_size = str->size + append_str->length;
	if(new_size > str->size)
	{
		if(swString_extend(str, new_size) < 0)
		{
			return SW_ERR;
		}
	}
	memcpy(str->str + str->length, append_str->str, append_str->length);
	return SW_OK;
}

int swString_extend(swString *str, size_t new_size)
{
	if(new_size <= str->size)
	{
		swWarn("new_size <= size. extend failed.");
		return SW_ERR;
	}
	str->str = sw_realloc(str->str, new_size);
	if (str->str == NULL)
	{
		swWarn("realloc failed.");
		return SW_ERR;
	}
	return SW_OK;
}

uint32_t swoole_utf8_decode(u_char **p, size_t n)
{
	size_t len;
	uint32_t u, i, valid;

	u = **p;

	if (u >= 0xf0)
	{
		u &= 0x07;
		valid = 0xffff;
		len = 3;
	}
	else if (u >= 0xe0)
	{
		u &= 0x0f;
		valid = 0x7ff;
		len = 2;
	}
	else if (u >= 0xc2)
	{
		u &= 0x1f;
		valid = 0x7f;
		len = 1;
	}
	else
	{
		(*p)++;
		return 0xffffffff;
	}

	if (n - 1 < len)
	{
		return 0xfffffffe;
	}

	(*p)++;

	while (len)
	{
		i = *(*p)++;
		if (i < 0x80)
		{
			return 0xffffffff;
		}
		u = (u << 6) | (i & 0x3f);
		len--;
	}

	if (u > valid)
	{
		return u;
	}

	return 0xffffffff;
}

size_t swoole_utf8_length(u_char *p, size_t n)
{
	u_char c, *last;
	size_t len;

	last = p + n;

	for (len = 0; p < last; len++)
	{
		c = *p;
		if (c < 0x80)
		{
			p++;
			continue;
		}
		if (swoole_utf8_decode(&p, n) > 0x10ffff)
		{
			/* invalid UTF-8 */
			return n;
		}
	}
	return len;
}


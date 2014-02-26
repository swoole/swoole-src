#include "swoole.h"
#include "array.h"

static int swArray_extend(swArray *array);

swArray *swArray_new(int page_size, size_t item_size, int flag)
{
	swArray *array = sw_malloc(sizeof(swArray));
	if (array == NULL)
	{
		swWarn("malloc[0] failed.");
		return NULL;
	}
	array->items = sw_malloc(sizeof(void*) * SW_ARRAY_PAGE_MAX);
	if (array->items == NULL)
	{
		sw_free(array);
		swWarn("malloc[1] failed.");
	}
	array->flag = flag;
	array->item_size = item_size;
	array->page_size = page_size;
	swArray_extend(array);
	return array;
}

void swArray_free(swArray *array)
{
	int i;
	for (i = 0; i < array->page_num; i++)
	{
		sw_free(array->items[i]);
	}
	sw_free(array->items);
	sw_free(array);
}

int swArray_extend(swArray *array)
{
	if (array->page_num == SW_ARRAY_PAGE_MAX)
	{
		swWarn("max page_num is %d", array->page_num);
		return SW_ERR;
	}
	array->items[array->page_num] = sw_calloc(array->page_size, array->item_size);
	if (array->items[0] == NULL)
	{
		sw_free(array);
		swWarn("malloc[1] failed.");
	}
	array->page_num++;
	return SW_OK;
}

uint32_t swArray_push(swArray *array, void *data)
{
	int n = array->item_num;
	array->item_num++;
	if (array->item_num >= (array->page_num * array->page_size))
	{
		if (swArray_extend(array) < 0)
		{
			return SW_ERR;
		}
	}
	return n;
}

void *swArray_fetch(swArray *array, uint32_t n)
{
	int page = n / array->page_size;
	if (page > array->page_num)
	{
		swWarn("fetch index[%d] out of array", n);
		return NULL;
	}
	int offset = n - (page * array->page_size);
	return array->items[page] + (offset * array->item_size);
}

#ifndef _SW_ARRAY_H_
#define _SW_ARRAY_H_

/**
 * 默认swArray_elem指针数组的长度为10,也就是最多可以管理(SW_ARRAY_PAGE_MAX*page_size)个元素
 */
#define SW_ARRAY_PAGE_MAX      128

typedef struct
{
	void **items;
	uint16_t page_num;
	uint16_t page_size;
	size_t item_size;
	uint32_t item_num;
	char flag;
} swArray;

swArray *swArray_new(int page_size, size_t elem_size, int flag);
void swArray_free(swArray *array);
uint32_t swArray_push(swArray *array, void *data);
void *swArray_fetch(swArray *array, uint32_t n);

#endif /* _SW_ARRAY_H_ */

#ifndef _SW_ARRAY_H_
#define _SW_ARRAY_H_

/**
 * 默认swArray_items指针数组的长度为SW_ARRAY_PAGE_MAX,也就是最多可以管理(SW_ARRAY_PAGE_MAX*page_size)个元素
 */
#define SW_ARRAY_PAGE_MAX      128

typedef struct
{
	void **pages;
	uint16_t page_num;
	uint16_t page_size;
	size_t item_size;
	uint32_t item_num;
	char flag;
} swArray;

#define swArray_page(array, n)      ((n) / (array)->page_size)
#define swArray_offset(array, n)    ((n) % (array)->page_size)

swArray *swArray_new(int page_size, size_t elem_size, int flag);
void swArray_free(swArray *array);
uint32_t swArray_push(swArray *array, void *data);
void *swArray_fetch(swArray *array, uint32_t n);

#endif /* _SW_ARRAY_H_ */

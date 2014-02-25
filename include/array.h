#ifndef _SW_ARRAY_H_
#define _SW_ARRAY_H_

/**
 * 默认swArray_elem指针数组的长度为10,也就是最多可以管理(SW_ARRAY_SLICE_N*slice_len)个元素
 * 如果超过将自动扩容
 */
#define SW_ARRAY_SLICE_N       10

typedef struct
{
	swArray_elem **elems;
	uint16_t slice_num;
	uint16_t slice_size;  //每次扩容的尺寸
	size_t size;
} swArray;

typedef struct
{
	char tag;    //0: EMPTY
	char data[0];
} swArray_elem;

swArray *swArray_new(int slice_len, size_t elem_size, int flag);
void swArray_free(swArray *array);
void *swArray_push(swArray *array, void *data);
void *swArray_fetch(swArray *array, uint32_t n);

#endif /* _SW_ARRAY_H_ */

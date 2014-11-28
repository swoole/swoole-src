#ifndef _SW_ARRAY_H_
#define _SW_ARRAY_H_

/**
 * 默认swArray->pages指针数组的长度为SW_ARRAY_PAGE_MAX,也就是最多可以管理(SW_ARRAY_PAGE_MAX*page_size)个元素
 */
#define SW_ARRAY_PAGE_MAX      128

typedef struct
{
    void **pages;
    uint16_t page_num;
    uint16_t page_size;
    uint32_t item_size;
    uint32_t item_num;
    uint32_t offset;
    char flag;
} swArray;

#define swArray_page(array, n)      ((n) / (array)->page_size)
#define swArray_offset(array, n)    ((n) % (array)->page_size)

swArray *swArray_new(int page_size, size_t item_size, int flag);
void swArray_free(swArray *array);
void *swArray_fetch(swArray *array, uint32_t n);
int swArray_store(swArray *array, uint32_t n, void *data);
int swArray_push(swArray *array, void *data);

#endif /* _SW_ARRAY_H_ */

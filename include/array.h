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
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#ifndef _SW_ARRAY_H_
#define _SW_ARRAY_H_

/**
 * 默认swArray->pages指针数组的长度为SW_ARRAY_PAGE_MAX,也就是最多可以管理(SW_ARRAY_PAGE_MAX*page_size)个元素
 */
#define SW_ARRAY_PAGE_MAX      1024

typedef struct _swArray
{
    void **pages;

    /**
     * 页的数量
     */
    uint16_t page_num;

    /**
     * 每页的数据元素个数
     */
    uint16_t page_size;

    /**
     * 数据元素的尺寸
     */
    uint32_t item_size;

    /**
     * 数据个数
     */
    uint32_t item_num;
    uint32_t offset;
} swArray;

#define swArray_page(array, n)      ((n) / (array)->page_size)
#define swArray_offset(array, n)    ((n) % (array)->page_size)

swArray *swArray_new(int page_size, size_t item_size);
void swArray_free(swArray *array);
void *swArray_fetch(swArray *array, uint32_t n);
int swArray_store(swArray *array, uint32_t n, void *data);
void *swArray_alloc(swArray *array, uint32_t n);
int swArray_append(swArray *array, void *data);
int swArray_extend(swArray *array);
void swArray_clear(swArray *array);

#endif /* _SW_ARRAY_H_ */

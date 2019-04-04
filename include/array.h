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
 * The default swArray->pages pointer array is SW_ARRAY_PAGE_MAX,
 * it means you can manage up to (SW_ARRAY_PAGE_MAX*page_size) elements
 */
#define SW_ARRAY_PAGE_MAX      1024

typedef struct _swArray
{
    void **pages;

    /**
     * number of page
     */
    uint16_t page_num;

    /**
     * number of data elements per page
     */
    uint16_t page_size;

    /**
     * data element size
     */
    uint32_t item_size;

    /**
     * number of data
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

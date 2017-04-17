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



#ifndef SW_TABLE_H_
#define SW_TABLE_H_

#include "atomic.h"
#include "hashmap.h"
#include "hash.h"

typedef struct _swTableRow
{
    sw_atomic_t lock;
    /**
     * 1:used, 0:empty
     */
    uint8_t active;
    /**
     * next slot
     */
    struct _swTableRow *next;
    /**
     * Hash Key
     */
    char key[SW_TABLE_KEY_SIZE];
    char data[0];
} swTableRow;

typedef struct
{
    uint32_t absolute_index;
    uint32_t collision_index;
    swTableRow *row;
} swTable_iterator;

typedef struct
{
    swHashMap *columns;
    uint16_t column_num;
    swLock lock;
    uint32_t size;
    uint32_t mask;
    uint32_t item_size;

    /**
     * total rows that in active state(shm)
     */
    sw_atomic_t row_num;

    swTableRow **rows;
    swMemoryPool *pool;

    uint32_t compress_threshold;

    swTable_iterator *iterator;

    void *memory;
} swTable;

typedef struct
{
   uint8_t type;
   uint32_t size;
   swString* name;
   uint16_t index;
} swTableColumn;

enum swoole_table_type
{
    SW_TABLE_INT = 1,
    SW_TABLE_INT8,
    SW_TABLE_INT16,
    SW_TABLE_INT32,
#ifdef __x86_64__
    SW_TABLE_INT64,
#endif
    SW_TABLE_FLOAT,
    SW_TABLE_STRING,
};

enum swoole_table_find
{
    SW_TABLE_FIND_EQ = 1,
    SW_TABLE_FIND_NEQ,
    SW_TABLE_FIND_GT,
    SW_TABLE_FIND_LT,
    SW_TABLE_FIND_LEFTLIKE,
    SW_TABLE_FIND_RIGHTLIKE,
    SW_TABLE_FIND_LIKE,
};

swTable* swTable_new(uint32_t rows_size);
int swTable_create(swTable *table);
void swTable_free(swTable *table);
int swTableColumn_add(swTable *table, char *name, int len, int type, int size);
swTableRow* swTableRow_set(swTable *table, char *key, int keylen, sw_atomic_t **rowlock);
swTableRow* swTableRow_get(swTable *table, char *key, int keylen, sw_atomic_t **rowlock);

void swTable_iterator_rewind(swTable *table);
swTableRow* swTable_iterator_current(swTable *table);
void swTable_iterator_forward(swTable *table);
int swTableRow_del(swTable *table, char *key, int keylen);

static sw_inline swTableColumn* swTableColumn_get(swTable *table, char *column_key, int keylen)
{
    return swHashMap_find(table->columns, column_key, keylen);
}

typedef uint32_t swTable_string_length_t;

static sw_inline void swTableRow_set_value(swTableRow *row, swTableColumn * col, void *value, int vlen)
{
    switch(col->type)
    {
    case SW_TABLE_INT8:
        memcpy(row->data + col->index, value, 1);
        break;
    case SW_TABLE_INT16:
        memcpy(row->data + col->index, value, 2);
        break;
    case SW_TABLE_INT32:
        memcpy(row->data + col->index, value, 4);
        break;
#ifdef __x86_64__
    case SW_TABLE_INT64:
        memcpy(row->data + col->index, value, 8);
        break;
#endif
    case SW_TABLE_FLOAT:
        memcpy(row->data + col->index, value, sizeof(double));
        break;
    default:
        if (vlen > (col->size - sizeof(swTable_string_length_t)))
        {
            swWarn("string is too long.");
            vlen = col->size - sizeof(swTable_string_length_t);
        }
        memcpy(row->data + col->index, &vlen, sizeof(swTable_string_length_t));
        memcpy(row->data + col->index + sizeof(swTable_string_length_t), value, vlen);
        break;
    }
}

#endif /* SW_TABLE_H_ */

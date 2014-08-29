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
#include "table.h"

static void swTableColumn_free(swTableColumn *col)
{
    swString_free(col->name);
    sw_free(col);
}

swTable* swTable_new(uint32_t rows_size)
{
    swTable *table = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swTable));
    if (table == NULL)
    {
        return NULL;
    }
    if (swMutex_create(&table->lock, 1) < 0)
    {
        swWarn("mutex create failed.");
        return NULL;
    }
    table->columns = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, (swHashMap_dtor)swTableColumn_free);
    if (!table->columns)
    {
        return NULL;
    }
    table->size = rows_size;
    return table;
}

int swTableColumn_add(swTable *table, char *name, int len, int type, int size)
{
    swTableColumn *col = sw_malloc(sizeof(swTableColumn));
    col->name = swString_dup(name, len);
    if (!col->name)
    {
        return SW_ERR;
    }
    switch(type)
    {
    case SW_TABLE_INT:
        switch(size)
        {
        case 1:
            col->size = 1;
            col->type = SW_TABLE_INT8;
            break;
        case 2:
            col->size = 2;
            col->type = SW_TABLE_INT16;
            break;
        case 4:
            col->size = 4;
            col->type = SW_TABLE_INT32;
            break;
        default:
            col->size = 8;
            col->type = SW_TABLE_INT64;
            break;
        }
        break;
    case SW_TABLE_FLOAT:
        col->size = 8;
        col->type = SW_TABLE_FLOAT;
        break;
    default:
        col->size = size + sizeof(uint16_t);
        col->type = SW_TABLE_STRING;
        break;
    }
    col->index = table->item_size;
    table->item_size += col->size;
    table->column_num ++;
    return swHashMap_add(table->columns, name, len, col, NULL);
}

int swTable_create(swTable *table)
{
    uint32_t row_num = table->size * (1 + SW_TABLE_CONFLICT_PROPORTION);
    uint32_t row_memory_size = sizeof(swTableRow) + table->item_size;

    size_t memory_size = row_num * row_memory_size;
    void *memory = sw_shm_malloc(memory_size);
    if (memory == NULL)
    {
        return SW_ERR;
    }
    table->memory = memory;
    table->rows = memory;

    int i;
    for (i = 0; i < table->size; i++)
    {
        table->rows[i] = memory + (row_memory_size * i);
    }
    memory += row_memory_size * table->size;
    memory_size -= row_memory_size * table->size;
    table->pool = swFixedPool_new2(row_memory_size, memory, memory_size);
    return SW_OK;
}

void swTable_free(swTable *table)
{
    swHashMap_free(table->columns);
    sw_shm_free(table->memory);
}

static sw_inline swTableRow* swTable_hash(swTable *table, char *key, int keylen)
{
    uint64_t hashv = swoole_hash_austin(key, keylen);
    uint32_t index = hashv & (table->size - 1);
    return table->rows[index];
}

swTableRow* swTableRow_set(swTable *table, char *key, int keylen)
{
    swTableRow *row = swTable_hash(table, key, keylen);
    uint32_t crc32 = swoole_crc32(key, keylen);

    sw_spinlock(&row->lock);
    if (row->active)
    {
        for (;;)
        {
            if (row->crc32 == crc32)
            {
                break;
            }
            else if (row->next == NULL)
            {
                table->lock.lock(&table->lock);
                swTableRow *new_row = table->pool->alloc(table->pool, 0);
                table->lock.unlock(&table->lock);

                if (!new_row)
                {
                    sw_spinlock_release(&row->lock);
                    return NULL;
                }

                row->next = new_row;
                row = new_row;
                break;
            }
            else
            {
                row = row->next;
            }
        }
    }
    row->crc32 = crc32;
    row->active = 1;
    swTrace("row=%p, crc32=%u, key=%s\n", row, crc32, key);
    sw_spinlock_release(&row->lock);
    return row;
}

swTableRow* swTableRow_get(swTable *table, char *key, int keylen)
{
    swTableRow *row = swTable_hash(table, key, keylen);
    uint32_t crc32 = swoole_crc32(key, keylen);
    sw_atomic_t *lock = &row->lock;

    swTrace("row=%p, crc32=%u, key=%s\n", row, crc32, key);

    sw_spinlock(lock);
    for (;;)
    {
        if (row->crc32 == crc32)
        {
            if (!row->active)
            {
                row = NULL;
            }
            break;
        }
        else if (row->next == NULL)
        {
            row = NULL;
            break;
        }
        else
        {
            row = row->next;
        }
    }
    sw_spinlock_release(lock);
    return row;
}

int swTableRow_del(swTable *table, char *key, int keylen)
{
    swTableRow *row = swTable_hash(table, key, keylen);
    uint32_t crc32 = swoole_crc32(key, keylen);

    sw_spinlock(&row->lock);
    while (row->active)
    {
        for (;;)
        {
            if (row->crc32 == crc32)
            {
                table->lock.lock(&table->lock);
                table->pool->free(table->pool, row);
                table->lock.unlock(&table->lock);
                break;
            }
            else if (row->next == NULL)
            {
                return SW_ERR;
            }
            else
            {
                row = row->next;
            }
        }
    }
    row->active = 0;
    sw_spinlock_release(&row->lock);
    return SW_OK;
}

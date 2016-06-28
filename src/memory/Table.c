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

#include "swoole.h"
#include "table.h"

#ifdef SW_TABLE_DEBUG
static int conflict_count = 0;
static int insert_count = 0;
#endif

static void swTable_compress_list(swTable *table);
static void swTableColumn_free(swTableColumn *col);

static void swTableColumn_free(swTableColumn *col)
{
    swString_free(col->name);
    sw_free(col);
}

static void swTable_compress_list(swTable *table)
{
    table->lock.lock(&table->lock);

    swTableRow **tmp = sw_malloc(sizeof(swTableRow *) * table->size);
    if (!tmp)
    {
        swWarn("malloc() failed, cannot compress the jump table.");
        goto unlock;
    }

    int i, tmp_i = 0;
    for (i = 0; i < table->list_n; i++)
    {
        if (table->rows_list[i] != NULL)
        {
            tmp[tmp_i] = table->rows_list[i];
            tmp[tmp_i]->list_index = tmp_i;
            tmp_i++;
        }
    }

    memcpy(table->rows_list, tmp, sizeof(swTableRow *) * tmp_i);
    sw_free(tmp);
    table->list_n = tmp_i;

    unlock: table->lock.unlock(&table->lock);
}

swTable* swTable_new(uint32_t rows_size)
{
    if (rows_size >= 0x80000000)
    {
        rows_size = 0x80000000;
    }
    else
    {
        uint32_t i = 10;
        while ((1U << i) < rows_size)
        {
            i++;
        }
        rows_size = 1 << i;
    }

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
    table->iterator = sw_malloc(sizeof(swTable_iterator));
    if (!table->iterator)
    {
        swWarn("malloc failed.");
        return NULL;
    }
    table->columns = swHashMap_new(SW_HASHMAP_INIT_BUCKET_N, (swHashMap_dtor)swTableColumn_free);
    if (!table->columns)
    {
        return NULL;
    }

    table->size = rows_size;
    table->mask = rows_size - 1;

    bzero(table->iterator, sizeof(swTable_iterator));
    table->memory = NULL;
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
#ifdef __x86_64__
        case 8:
            col->size = 8;
            col->type = SW_TABLE_INT64;
            break;
#endif
        default:
            col->size = 4;
            col->type = SW_TABLE_INT32;
            break;
        }
        break;
    case SW_TABLE_FLOAT:
        col->size = sizeof(double);
        col->type = SW_TABLE_FLOAT;
        break;
    case SW_TABLE_STRING:
        col->size = size + sizeof(swTable_string_length_t);
        col->type = SW_TABLE_STRING;
        break;
    default:
        swWarn("unkown column type.");
        return SW_ERR;
    }
    col->index = table->item_size;
    table->item_size += col->size;
    table->column_num ++;
    return swHashMap_add(table->columns, name, len, col);
}

int swTable_create(swTable *table)
{
    uint32_t row_num = table->size * (1 + SW_TABLE_CONFLICT_PROPORTION);

    //header + data
    uint32_t row_memory_size = sizeof(swTableRow) + table->item_size;

    /**
     * row data & header
     */
    size_t memory_size = row_num * row_memory_size;

    /**
     * row point
     */
    memory_size += table->size * sizeof(swTableRow *);

    /**
     * memory pool for conflict rows
     */
    memory_size += sizeof(swMemoryPool) + sizeof(swFixedPool) + ((row_num - table->size) * sizeof(swFixedPool_slice));

    /**
     * for iterator, Iterate through all the elements
     */
    memory_size += table->size * sizeof(swTableRow *);

    void *memory = sw_shm_malloc(memory_size);
    if (memory == NULL)
    {
        return SW_ERR;
    }

    memset(memory, 0, memory_size);
    table->memory = memory;
    table->compress_threshold = table->size * SW_TABLE_COMPRESS_PROPORTION;
    table->rows_list = memory;

    memory += table->size * sizeof(swTableRow *);
    memory_size -= table->size * sizeof(swTableRow *);

    table->rows = memory;
    memory += table->size * sizeof(swTableRow *);
    memory_size -= table->size * sizeof(swTableRow *);

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
#ifdef SW_TABLE_DEBUG
    printf("swoole_table: size=%d, conflict_count=%d, insert_count=%d\n", table->size, conflict_count, insert_count);
#endif

    swHashMap_free(table->columns);
    sw_free(table->iterator);
    if (table->memory)
    {
        sw_shm_free(table->memory);
    }
}

static sw_inline swTableRow* swTable_hash(swTable *table, char *key, int keylen)
{
#ifdef SW_TABLE_USE_PHP_HASH
    uint64_t hashv = swoole_hash_php(key, keylen);
#else
    uint64_t hashv = swoole_hash_austin(key, keylen);
#endif
    uint32_t index = hashv & table->mask;
    assert(index < table->size);
    return table->rows[index];
}

void swTable_iterator_rewind(swTable *table)
{
    bzero(table->iterator, sizeof(swTable_iterator));
}

static sw_inline swTableRow* swTable_iterator_get(swTable *table, uint32_t index)
{
    table->lock.lock(&table->lock);
    swTableRow * row = table->rows_list[index];
    table->lock.unlock(&table->lock);
    return row;
}

swTableRow* swTable_iterator_current(swTable *table)
{
    swTableRow *row = NULL;

    for (; table->iterator->absolute_index < table->list_n; table->iterator->absolute_index++)
    {
        row = swTable_iterator_get(table, table->iterator->absolute_index);
        if (row == NULL)
        {
            table->iterator->skip_count++;
            continue;
        }
        else
        {
            break;
        }
    }
    if (table->iterator->collision_index == 0)
    {
        return row;
    }
    int i;
    for (i = 0; i < table->iterator->collision_index; i++)
    {
        row = row->next;
    }
    return row;
}

void swTable_iterator_forward(swTable *table)
{
    for ( ; table->iterator->absolute_index < table->list_n; table->iterator->absolute_index++)
    {
        swTableRow *row = swTable_iterator_get(table, table->iterator->absolute_index);
        if (row == NULL)
        {
            continue;
        }
        else if (row->next == NULL)
        {
            table->iterator->absolute_index++;
            return;
        }
        else
        {
            int i = 0;
            for (;; i++)
            {
                row = row->next;
                if (i == table->iterator->collision_index)
                {
                    if (row == NULL)
                    {
                        table->iterator->absolute_index++;
                        table->iterator->collision_index = 0;
                    }
                    else
                    {
                        table->iterator->collision_index++;
                    }
                    return;
                }
            }
        }
    }
}

swTableRow* swTableRow_get(swTable *table, char *key, int keylen, sw_atomic_t **rowlock)
{
    if (keylen > SW_TABLE_KEY_SIZE)
    {
        keylen = SW_TABLE_KEY_SIZE;
    }

    swTableRow *row = swTable_hash(table, key, keylen);
    sw_atomic_t *lock = &row->lock;
    sw_spinlock(lock);
    *rowlock = lock;

    for (;;)
    {
        if (strncmp(row->key, key, keylen) == 0)
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

    return row;
}

swTableRow* swTableRow_set(swTable *table, char *key, int keylen, sw_atomic_t **rowlock)
{
    if (keylen > SW_TABLE_KEY_SIZE)
    {
        keylen = SW_TABLE_KEY_SIZE;
    }

    swTableRow *row = swTable_hash(table, key, keylen);
    sw_atomic_t *lock = &row->lock;
    sw_spinlock(lock);
    *rowlock = lock;

    if (row->active)
    {
        for (;;)
        {
            if (strncmp(row->key, key, keylen) == 0)
            {
                break;
            }
            else if (row->next == NULL)
            {
                table->lock.lock(&table->lock);
                swTableRow *new_row = table->pool->alloc(table->pool, 0);

#ifdef SW_TABLE_DEBUG
                conflict_count ++;
#endif
                table->lock.unlock(&table->lock);

                if (!new_row)
                {
                    return NULL;
                }
                //add row_num
                bzero(new_row, sizeof(swTableRow));
                sw_atomic_fetch_add(&(table->row_num), 1);
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
    else
    {
#ifdef SW_TABLE_DEBUG
        insert_count ++;
#endif

        sw_atomic_fetch_add(&(table->row_num), 1);

        // when the root node become active, we may need compress the jump table
        if (table->list_n >= table->size - 1)
        {
            swTable_compress_list(table);
        }

        table->lock.lock(&table->lock);
        table->rows_list[table->list_n] = row;
        table->lock.unlock(&table->lock);

        row->list_index = table->list_n;
        sw_atomic_fetch_add(&table->list_n, 1);
    }

    memcpy(row->key, key, keylen);
    row->active = 1;
    return row;
}

int swTableRow_del(swTable *table, char *key, int keylen)
{
    if (keylen > SW_TABLE_KEY_SIZE)
    {
        keylen = SW_TABLE_KEY_SIZE;
    }

    swTableRow *row = swTable_hash(table, key, keylen);
    sw_atomic_t *lock = &row->lock;
    //no exists
    if (!row->active)
    {
        return SW_ERR;
    }

    sw_spinlock(lock);
    if (row->next == NULL)
    {
        if (strncmp(row->key, key, keylen) == 0)
        {
            table->lock.lock(&table->lock);
            table->rows_list[row->list_index] = NULL;
            table->lock.unlock(&table->lock);

            if (table->iterator->skip_count > table->compress_threshold)
            {
                swTable_compress_list(table);
            }
            bzero(row, sizeof(swTableRow) + table->item_size);
            goto delete_element;
        }
        else
        {
            goto not_exists;
        }
    }
    else
    {
        swTableRow *tmp = row;
        swTableRow *prev = NULL;

        while (tmp)
        {
            if ((strncmp(tmp->key, key, keylen) == 0))
            {
                break;
            }
            prev = tmp;
            tmp = tmp->next;
        }

        if (tmp == NULL)
        {
            not_exists:
            sw_spinlock_release(lock);
            return SW_ERR;
        }

        //when the deleting element is root, we should move the first element's data to root,
        //and remove the element from the collision list.
        if (tmp == row)
        {
            tmp = tmp->next;
            row->next = tmp->next;
            memcpy(row->key, tmp->key, strlen(tmp->key));

            if (table->iterator->skip_count > table->compress_threshold)
            {
                swTable_compress_list(table);
            }

            memcpy(row->data, tmp->data, table->item_size);
        }
        if (prev)
        {
            prev->next = tmp->next;
        }
        table->lock.lock(&table->lock);
        bzero(tmp, sizeof(swTableRow) + table->item_size);
        table->pool->free(table->pool, tmp);
        table->lock.unlock(&table->lock);
    }

    delete_element:
    sw_atomic_fetch_sub(&(table->row_num), 1);
    sw_spinlock_release(lock);

    return SW_OK;
}

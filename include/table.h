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

#pragma once

#include "atomic.h"
#include "hash.h"
#include <string>
#include <vector>
#include <unordered_map>

typedef uint32_t swTable_string_length_t;

struct swTableRow
{
    sw_atomic_t lock;
    pid_t lock_pid;
    /**
     * 1:used, 0:empty
     */
    uint8_t active;
    uint8_t key_len;
    /**
     * next slot
     */
    swTableRow *next;
    /**
     * Hash Key
     */
    char key[SW_TABLE_KEY_SIZE];
    char data[0];
};

struct swTable_iterator
{
    uint32_t absolute_index;
    uint32_t collision_index;
    swTableRow *row;
};

enum swTableColumn_type
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

struct swTableColumn
{
    enum swTableColumn_type type;
    uint32_t size;
    std::string name;
    size_t index;

    swTableColumn(const std::string &_name, enum swTableColumn_type _type, size_t _size) :
            name(_name)
    {
        index = 0;
        switch (_type)
        {
        case SW_TABLE_INT:
            switch (_size)
            {
            case 1:
                size = 1;
                type = SW_TABLE_INT8;
                break;
            case 2:
                size = 2;
                type = SW_TABLE_INT16;
                break;
#ifdef __x86_64__
            case 8:
                size = 8;
                type = SW_TABLE_INT64;
                break;
#endif
            default:
                size = 4;
                type = SW_TABLE_INT32;
                break;
            }
            break;
        case SW_TABLE_FLOAT:
            size = sizeof(double);
            type = SW_TABLE_FLOAT;
            break;
        case SW_TABLE_STRING:
            size = _size + sizeof(swTable_string_length_t);
            type = SW_TABLE_STRING;
            break;
        default:
            abort();
            break;
        }
    }
};

struct swTable
{
    std::unordered_map<std::string, swTableColumn*> *column_map;
    std::vector<swTableColumn*> *column_list;
    swLock lock;
    size_t size;
    size_t mask;
    size_t item_size;
    size_t memory_size;
    float conflict_proportion;

    /**
     * total rows that in active state(shm)
     */
    sw_atomic_t row_num;

    swTableRow **rows;
    swMemoryPool *pool;

    swTable_iterator *iterator;
    uint64_t (*hash_func)(const char *key, size_t len);

    void *memory;
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

swTable* swTable_new(uint32_t rows_size, float conflict_proportion);
size_t swTable_get_memory_size(swTable *table);
int swTable_create(swTable *table);
void swTable_free(swTable *table);
bool swTableColumn_add(swTable *table, const std::string &name, enum swTableColumn_type type, size_t size);
swTableRow* swTableRow_set(swTable *table, const char *key, int keylen, swTableRow **rowlock);
swTableRow* swTableRow_get(swTable *table, const char *key, int keylen, swTableRow **rowlock);

void swTable_iterator_rewind(swTable *table);
swTableRow* swTable_iterator_current(swTable *table);
void swTable_iterator_forward(swTable *table);
int swTableRow_del(swTable *table, const char *key, int keylen);

static sw_inline swTableColumn* swTableColumn_get(swTable *table, const std::string &key)
{
    auto i = table->column_map->find(key);
    if (i == table->column_map->end())
    {
        return nullptr;
    }
    else
    {
        return i->second;
    }
}

static sw_inline void swTableRow_lock(swTableRow *row)
{
    sw_atomic_t *lock = &row->lock;
    uint32_t i, n;
    while(1)
    {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
        {
            _success: row->lock_pid = SwooleG.pid;
            return;
        }
        if (SW_CPU_NUM > 1)
        {
            for (n = 1; n < SW_SPINLOCK_LOOP_N; n <<= 1)
            {
                for (i = 0; i < n; i++)
                {
                    sw_atomic_cpu_pause();
                }
                if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
                {
                    goto _success;
                }
            }
        }
        if (kill(row->lock_pid, 0) < 0 && errno == ESRCH)
        {
            *lock = 1;
            goto _success;
        }
        swYield();
    }
}

static sw_inline void swTableRow_unlock(swTableRow *row)
{
    sw_spinlock_release(&row->lock);
}

static sw_inline void swTableRow_set_value(swTableRow *row, swTableColumn *col, void *value, size_t vlen)
{
    int8_t _i8;
    int16_t _i16;
    int32_t _i32;
#ifdef __x86_64__
    int64_t _i64;
#endif
    switch(col->type)
    {
    case SW_TABLE_INT8:
        _i8 = *(int8_t *) value;
        memcpy(row->data + col->index, &_i8, 1);
        break;
    case SW_TABLE_INT16:
        _i16 =  *(int16_t *) value;
        memcpy(row->data + col->index, &_i16, 2);
        break;
    case SW_TABLE_INT32:
        _i32 =  *(int32_t *) value;
        memcpy(row->data + col->index, &_i32, 4);
        break;
#ifdef __x86_64__
    case SW_TABLE_INT64:
        _i64 =  *(int64_t *) value;
        memcpy(row->data + col->index, &_i64, 8);
        break;
#endif
    case SW_TABLE_FLOAT:
        memcpy(row->data + col->index, value, sizeof(double));
        break;
    default:
        if (vlen > (col->size - sizeof(swTable_string_length_t)))
        {
            swWarn("[key=%s,field=%s]string value is too long", row->key, col->name.c_str());
            vlen = col->size - sizeof(swTable_string_length_t);
        }
        memcpy(row->data + col->index, &vlen, sizeof(swTable_string_length_t));
        memcpy(row->data + col->index + sizeof(swTable_string_length_t), value, vlen);
        break;
    }
}

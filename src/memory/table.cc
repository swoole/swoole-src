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

#include "table.h"

//#define SW_TABLE_DEBUG 1
#define SW_TABLE_USE_PHP_HASH

#ifdef SW_TABLE_DEBUG
static int conflict_count = 0;
static int insert_count = 0;
static int conflict_max_level = 0;
#endif

static inline void swTable_check_key_length(uint16_t *keylen) {
    if (*keylen >= SW_TABLE_KEY_SIZE) {
        *keylen = SW_TABLE_KEY_SIZE - 1;
    }
}

swTable *swTable_new(uint32_t rows_size, float conflict_proportion) {
    if (rows_size >= 0x80000000) {
        rows_size = 0x80000000;
    } else {
        uint32_t i = 6;
        while ((1U << i) < rows_size) {
            i++;
        }
        rows_size = 1 << i;
    }

    if (conflict_proportion > 1.0) {
        conflict_proportion = 1.0;
    } else if (conflict_proportion < SW_TABLE_CONFLICT_PROPORTION) {
        conflict_proportion = SW_TABLE_CONFLICT_PROPORTION;
    }

    swTable *table = (swTable *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swTable));
    if (table == nullptr) {
        return nullptr;
    }
    if (swMutex_create(&table->lock, 1) < 0) {
        swWarn("mutex create failed");
        return nullptr;
    }
    table->iterator = new swTable_iterator;
    table->column_map = new std::unordered_map<std::string, swTableColumn *>;
    table->column_list = new std::vector<swTableColumn *>;
    table->size = rows_size;
    table->mask = rows_size - 1;
    table->conflict_proportion = conflict_proportion;
#ifdef SW_TABLE_USE_PHP_HASH
    table->hash_func = swoole_hash_php;
#else
    table->hash_func = swoole_hash_austin;
#endif

    sw_memset_zero(table->iterator, sizeof(swTable_iterator));
    table->memory = nullptr;

    return table;
}

bool swTableColumn_add(swTable *table, const std::string &name, enum swTableColumn_type type, size_t size) {
    if (type < SW_TABLE_INT || type > SW_TABLE_STRING) {
        swWarn("unkown column type");
        return false;
    }

    swTableColumn *col = new swTableColumn(name, type, size);
    col->index = table->item_size;
    table->item_size += col->size;
    table->column_map->emplace(name, col);
    table->column_list->push_back(col);

    return true;
}

size_t swTable_get_memory_size(swTable *table) {
    /**
     * table size + conflict size
     */
    size_t row_num = table->size * (1 + table->conflict_proportion);

    /*
     * header + data
     */
    size_t row_memory_size = sizeof(swTableRow) + table->item_size;

    /**
     * row data & header
     */
    size_t memory_size = row_num * row_memory_size;

    /**
     * memory pool for conflict rows
     */
    memory_size += sizeof(swMemoryPool) + sizeof(swFixedPool) + ((row_num - table->size) * sizeof(swFixedPool_slice));

    /**
     * for iterator, Iterate through all the elements
     */
    memory_size += table->size * sizeof(swTableRow *);

    return memory_size;
}

int swTable_create(swTable *table) {
    size_t memory_size = swTable_get_memory_size(table);
    size_t row_memory_size = sizeof(swTableRow) + table->item_size;

    void *memory = sw_shm_malloc(memory_size);
    if (memory == nullptr) {
        return SW_ERR;
    }

    table->memory_size = memory_size;
    table->memory = memory;

    table->rows = (swTableRow **) memory;
    memory = (char *) memory + table->size * sizeof(swTableRow *);
    memory_size -= table->size * sizeof(swTableRow *);

    for (size_t i = 0; i < table->size; i++) {
        table->rows[i] = (swTableRow *) ((char *) memory + (row_memory_size * i));
        memset(table->rows[i], 0, sizeof(swTableRow));
    }

    memory = (char *) memory + row_memory_size * table->size;
    memory_size -= row_memory_size * table->size;
    table->pool = swFixedPool_new2(row_memory_size, memory, memory_size);
    table->create_pid = SwooleG.pid;

    return SW_OK;
}

void swTable_free(swTable *table) {
#ifdef SW_TABLE_DEBUG
    printf("swoole_table: size=%d, conflict_count=%d, conflict_max_level=%d, insert_count=%d\n",
           table->size,
           conflict_count,
           conflict_max_level,
           insert_count);
#endif

    auto i = table->column_map->begin();
    while (i != table->column_map->end()) {
        delete i->second;
        table->column_map->erase(i++);
    }
    delete table->column_map;
    delete table->column_list;
    delete table->iterator;

    if (table->create_pid != SwooleG.pid) {
        return;
    }

    if (table->memory) {
        sw_shm_free(table->memory);
    }
    SwooleG.memory_pool->free(SwooleG.memory_pool, table);
}

static sw_inline swTableRow *swTable_hash(swTable *table, const char *key, int keylen) {
    uint64_t hashv = table->hash_func(key, keylen);
    uint64_t index = hashv & table->mask;
    assert(index < table->size);
    return table->rows[index];
}

void swTable_iterator_rewind(swTable *table) {
    sw_memset_zero(table->iterator, sizeof(swTable_iterator));
}

static sw_inline swTableRow *swTable_iterator_get(swTable *table, uint32_t index) {
    swTableRow *row = table->rows[index];
    return row->active ? row : nullptr;
}

swTableRow *swTable_iterator_current(swTable *table) {
    return table->iterator->row;
}

void swTable_iterator_forward(swTable *table) {
    for (; table->iterator->absolute_index < table->size; table->iterator->absolute_index++) {
        swTableRow *row = swTable_iterator_get(table, table->iterator->absolute_index);
        if (row == nullptr) {
            continue;
        } else if (row->next == nullptr) {
            table->iterator->absolute_index++;
            table->iterator->row = row;
            return;
        } else {
            uint32_t i = 0;
            for (;; i++) {
                if (row == nullptr) {
                    table->iterator->collision_index = 0;
                    break;
                }
                if (i == table->iterator->collision_index) {
                    table->iterator->collision_index++;
                    table->iterator->row = row;
                    return;
                }
                row = row->next;
            }
        }
    }
    table->iterator->row = nullptr;
}

swTableRow *swTableRow_get(swTable *table, const char *key, uint16_t keylen, swTableRow **rowlock) {
    swTable_check_key_length(&keylen);

    swTableRow *row = swTable_hash(table, key, keylen);
    *rowlock = row;
    swTableRow_lock(row);

    for (;;) {
        if (sw_mem_equal(row->key, row->key_len, key, keylen)) {
            if (!row->active) {
                row = nullptr;
            }
            break;
        } else if (row->next == nullptr) {
            row = nullptr;
            break;
        } else {
            row = row->next;
        }
    }

    return row;
}

static inline void swTableRow_init(swTable *table, swTableRow *new_row, const char *key, int keylen) {
    sw_memset_zero(new_row, sizeof(swTableRow) + table->item_size);
    memcpy(new_row->key, key, keylen);
    new_row->key[keylen] = '\0';
    new_row->key_len = keylen;
    new_row->active = 1;
    sw_atomic_fetch_add(&(table->row_num), 1);
}

swTableRow *swTableRow_set(swTable *table, const char *key, uint16_t keylen, swTableRow **rowlock) {
    swTable_check_key_length(&keylen);

    swTableRow *row = swTable_hash(table, key, keylen);
    *rowlock = row;
    swTableRow_lock(row);

#ifdef SW_TABLE_DEBUG
    int _conflict_level = 0;
#endif

    if (row->active) {
        for (;;) {
            if (sw_mem_equal(row->key, row->key_len, key, keylen)) {
                break;
            } else if (row->next == nullptr) {
                table->lock.lock(&table->lock);
                swTableRow *new_row = (swTableRow *) table->pool->alloc(table->pool, 0);

#ifdef SW_TABLE_DEBUG
                conflict_count++;
                if (_conflict_level > conflict_max_level) {
                    conflict_max_level = _conflict_level;
                }

#endif
                table->lock.unlock(&table->lock);
                if (!new_row) {
                    return nullptr;
                }
                swTableRow_init(table, new_row, key, keylen);
                row->next = new_row;
                row = new_row;
                break;
            } else {
                row = row->next;
#ifdef SW_TABLE_DEBUG
                _conflict_level++;
#endif
            }
        }
    } else {
#ifdef SW_TABLE_DEBUG
        insert_count++;
#endif
        swTableRow_init(table, row, key, keylen);
    }

    return row;
}

int swTableRow_del(swTable *table, const char *key, uint16_t keylen) {
    swTable_check_key_length(&keylen);

    swTableRow *row = swTable_hash(table, key, keylen);
    // no exists
    if (!row->active) {
        return SW_ERR;
    }

    swTableRow *tmp, *prev = nullptr;

    swTableRow_lock(row);
    if (row->next == nullptr) {
        if (sw_mem_equal(row->key, row->key_len, key, keylen)) {
            sw_memset_zero(row, sizeof(swTableRow));
            goto _delete_element;
        } else {
            goto _not_exists;
        }
    } else {
        tmp = row;
        while (tmp) {
            if (sw_mem_equal(tmp->key, tmp->key_len, key, keylen)) {
                break;
            }
            prev = tmp;
            tmp = tmp->next;
        }

        if (tmp == nullptr) {
        _not_exists:
            swTableRow_unlock(row);

            return SW_ERR;
        }

        // when the deleting element is root, we should move the first element's data to root,
        // and remove the element from the collision list.
        if (tmp == row) {
            tmp = tmp->next;
            row->next = tmp->next;
            memcpy(row->key, tmp->key, tmp->key_len + 1);
            row->key_len = tmp->key_len;
            memcpy(row->data, tmp->data, table->item_size);
        }
        if (prev) {
            prev->next = tmp->next;
        }
        table->lock.lock(&table->lock);
        sw_memset_zero(tmp, sizeof(swTableRow));
        table->pool->free(table->pool, tmp);
        table->lock.unlock(&table->lock);
    }

_delete_element:
    sw_atomic_fetch_sub(&(table->row_num), 1);
    swTableRow_unlock(row);

    return SW_OK;
}

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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole_table.h"

namespace swoole {

Table *Table::make(uint32_t rows_size, float conflict_proportion) {
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

    Table *table = (Table *) sw_mem_pool()->alloc(sizeof(*table));
    if (table == nullptr) {
        return nullptr;
    }
    table->mutex = new Mutex(Mutex::PROCESS_SHARED);
    table->iterator = nullptr;
    table->column_map = new std::unordered_map<std::string, TableColumn *>;
    table->column_list = new std::vector<TableColumn *>;
    table->size = rows_size;
    table->mask = rows_size - 1;
    table->conflict_proportion = conflict_proportion;
#ifdef SW_TABLE_USE_PHP_HASH
    table->hash_func = swoole_hash_php;
#else
    table->hash_func = swoole_hash_austin;
#endif

    return table;
}

void Table::free() {
    delete mutex;
    if (iterator) {
        delete iterator;
    }
    delete column_map;
    delete column_list;
}

bool Table::add_column(const std::string &_name, enum TableColumn::Type _type, size_t _size) {
    if (_type < TableColumn::TYPE_INT || _type > TableColumn::TYPE_STRING) {
        swoole_warning("unknown column type");
        return false;
    }

    TableColumn *col = new TableColumn(_name, _type, _size);
    col->index = item_size;
    item_size += col->size;
    column_map->emplace(_name, col);
    column_list->push_back(col);

    return true;
}

size_t Table::calc_memory_size() {
    /**
     * table size + conflict size
     */
    size_t _row_num = size * (1 + conflict_proportion);

    /*
     * header + data
     */
    size_t _row_memory_size = sizeof(TableRow) + item_size;

    /**
     * row data & header
     */
    size_t _memory_size = _row_num * _row_memory_size;

    /**
     * memory pool for conflict rows
     */
    _memory_size += FixedPool::sizeof_struct_impl() + ((_row_num - size) * FixedPool::sizeof_struct_slice());

    /**
     * for iterator, Iterate through all the elements
     */
    _memory_size += size * sizeof(TableRow *);

    swoole_trace("_memory_size=%lu, _row_num=%lu, _row_memory_size=%lu", _memory_size, _row_num, _row_memory_size);

    return _memory_size;
}

size_t Table::get_memory_size() {
    return memory_size;
}

uint32_t Table::get_available_slice_num() {
    lock();
    uint32_t num = pool->get_number_of_spare_slice();
    unlock();
    return num;
}

uint32_t Table::get_total_slice_num() {
    return pool->get_number_of_total_slice();
}

bool Table::create() {
    if (created) {
        return false;
    }

    size_t _memory_size = calc_memory_size();
    size_t _row_memory_size = sizeof(TableRow) + item_size;

    void *_memory = sw_shm_malloc(_memory_size);
    if (_memory == nullptr) {
        return false;
    }
    memory = _memory;

    rows = (TableRow **) _memory;
    _memory = (char *) _memory + size * sizeof(TableRow *);
    _memory_size -= size * sizeof(TableRow *);

    for (size_t i = 0; i < size; i++) {
        rows[i] = (TableRow *) ((char *) _memory + (_row_memory_size * i));
        memset(rows[i], 0, sizeof(TableRow));
    }

    _memory = (char *) _memory + _row_memory_size * size;
    _memory_size -= _row_memory_size * size;
    pool = new FixedPool(_row_memory_size, _memory, _memory_size, true);
    iterator = new TableIterator(_row_memory_size);
    memory_size = _memory_size;
    created = true;

    return true;
}

void Table::destroy() {
#ifdef SW_TABLE_DEBUG
    printf("swoole_table: size=%ld, conflict_count=%d, conflict_max_level=%d, insert_count=%d\n",
           size,
           conflict_count,
           conflict_max_level,
           insert_count);
#endif

    auto i = column_map->begin();
    while (i != column_map->end()) {
        delete i->second;
        column_map->erase(i++);
    }
    delete column_map;
    delete column_list;
    if (iterator) {
        delete iterator;
    }
    delete pool;
    if (memory) {
        sw_shm_free(memory);
    }
    memory = nullptr;
    delete mutex;
    sw_mem_pool()->free(this);
}

void TableRow::lock() {
    sw_atomic_t *lock = &lock_;
    uint32_t i, n;
    long t = 0;

    while (1) {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1)) {
        _success:
            lock_pid = SwooleG.pid;
            return;
        }
        if (SW_CPU_NUM > 1) {
            for (n = 1; n < SW_SPINLOCK_LOOP_N; n <<= 1) {
                for (i = 0; i < n; i++) {
                    sw_atomic_cpu_pause();
                }
                if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1)) {
                    goto _success;
                }
            }
        }
        /**
         * The process occupied by the resource no longer exists,
         * indicating that OOM occurred during the locking process,
         * forced to unlock
         */
        if (kill(lock_pid, 0) < 0 && errno == ESRCH) {
            *lock = 1;
            swoole_warning("lock process[%d] not exists, force unlock", lock_pid);
            goto _success;
        }
        /**
         * Mark time
         */
        if (t == 0) {
            t = swoole::time<std::chrono::milliseconds>(true);
        }
        /**
         * The deadlock time exceeds 2 seconds (SW_TABLE_FORCE_UNLOCK_TIME),
         * indicating that the lock process has OOM,
         * and the PID has been reused, forcing the unlock
         */
        else if ((swoole::time<std::chrono::milliseconds>(true) - t) > SW_TABLE_FORCE_UNLOCK_TIME) {
            *lock = 1;
            swoole_warning("timeout, force unlock");
            goto _success;
        }
        sw_yield();
    }
}

void Table::forward() {
    iterator->lock();
    for (; iterator->absolute_index < size; iterator->absolute_index++) {
        TableRow *row = get_by_index(iterator->absolute_index);
        if (row == nullptr) {
            continue;
        }
        row->lock();
        if (row->next == nullptr) {
            iterator->absolute_index++;
            memcpy(iterator->current_, row, iterator->row_memory_size_);
            row->unlock();
            iterator->unlock();
            return;
        } else {
            uint32_t i = 0;
            TableRow *tmp_row = row;
            for (;; i++) {
                if (tmp_row == nullptr) {
                    iterator->collision_index = 0;
                    break;
                }
                if (i == iterator->collision_index) {
                    iterator->collision_index++;
                    memcpy(iterator->current_, tmp_row, iterator->row_memory_size_);
                    row->unlock();
                    iterator->unlock();
                    return;
                }
                tmp_row = tmp_row->next;
            }
        }
        row->unlock();
    }
    sw_memset_zero(iterator->current_, sizeof(TableRow));
    iterator->unlock();
}

TableRow *Table::get(const char *key, uint16_t keylen, TableRow **rowlock) {
    check_key_length(&keylen);

    TableRow *row = hash(key, keylen);

    *rowlock = row;
    row->lock();

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

TableRow *Table::set(const char *key, uint16_t keylen, TableRow **rowlock, int *out_flags) {
    check_key_length(&keylen);

    TableRow *row = hash(key, keylen);
    *rowlock = row;
    row->lock();
    int _out_flags = 0;

    uint32_t _conflict_level = 1;

    if (row->active) {
        for (;;) {
            if (sw_mem_equal(row->key, row->key_len, key, keylen)) {
                break;
            } else if (row->next == nullptr) {
                conflict_count++;
                if (_conflict_level > conflict_max_level) {
                    conflict_max_level = _conflict_level;
                }
                TableRow *new_row = alloc_row();
                if (!new_row) {
                    return nullptr;
                }
                init_row(new_row, key, keylen);
                _out_flags |= SW_TABLE_FLAG_NEW_ROW;
                row->next = new_row;
                row = new_row;
                break;
            } else {
                row = row->next;
                _out_flags |= SW_TABLE_FLAG_CONFLICT;
                _conflict_level++;
            }
        }
    } else {
        init_row(row, key, keylen);
        _out_flags |= SW_TABLE_FLAG_NEW_ROW;
    }

    if (out_flags) {
        *out_flags = _out_flags;
    }

    if (_out_flags & SW_TABLE_FLAG_NEW_ROW) {
        sw_atomic_fetch_add(&(insert_count), 1);
    } else {
        sw_atomic_fetch_add(&(update_count), 1);
    }

    return row;
}

bool Table::del(const char *key, uint16_t keylen) {
    check_key_length(&keylen);

    TableRow *row = hash(key, keylen);
    // no exists
    if (!row->active) {
        return false;
    }

    TableRow *tmp, *prev = nullptr;

    row->lock();
    if (row->next == nullptr) {
        if (sw_mem_equal(row->key, row->key_len, key, keylen)) {
            row->clear();
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
            row->unlock();

            return false;
        }

        // when the deleting element is root, should move the first element's data to root,
        // and remove the element from the collision list.
        if (tmp == row) {
            tmp = tmp->next;
            row->next = tmp->next;
            memcpy(row->key, tmp->key, tmp->key_len + 1);
            row->key_len = tmp->key_len;
            memcpy(row->data, tmp->data, item_size);
        } else {
            prev->next = tmp->next;
        }
        free_row(tmp);
    }

_delete_element:
    sw_atomic_fetch_add(&(delete_count), 1);
    sw_atomic_fetch_sub(&(row_num), 1);
    row->unlock();

    return true;
}

void TableColumn::clear(TableRow *row) {
    if (type == TYPE_STRING) {
        row->set_value(this, nullptr, 0);
    } else if (type == TYPE_FLOAT) {
        double _value = 0;
        row->set_value(this, &_value, 0);
    } else {
        long _value = 0;
        row->set_value(this, &_value, 0);
    }
}

void TableRow::set_value(TableColumn *col, void *value, size_t vlen) {
    switch (col->type) {
    case TableColumn::TYPE_INT:
        memcpy(data + col->index, value, sizeof(long));
        break;
    case TableColumn::TYPE_FLOAT:
        memcpy(data + col->index, value, sizeof(double));
        break;
    default:
        if (vlen > (col->size - sizeof(TableStringLength))) {
            swoole_warning("[key=%s,field=%s]string value is too long", key, col->name.c_str());
            vlen = col->size - sizeof(TableStringLength);
        }
        if (value == nullptr) {
            vlen = 0;
        }
        memcpy(data + col->index, &vlen, sizeof(TableStringLength));
        if (vlen > 0) {
            memcpy(data + col->index + sizeof(TableStringLength), value, vlen);
        }
        break;
    }
}

void TableRow::get_value(TableColumn *col, double *dval) {
    memcpy(dval, data + col->index, sizeof(*dval));
}

void TableRow::get_value(TableColumn *col, long *lval) {
    memcpy(lval, data + col->index, sizeof(*lval));
}

void TableRow::get_value(TableColumn *col, char **value, TableStringLength *len) {
    memcpy(len, data + col->index, sizeof(*len));
    *value = data + col->index + sizeof(*len);
}

}  // namespace swoole

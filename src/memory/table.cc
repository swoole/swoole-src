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
#include "swoole_hash.h"
#include "swoole_util.h"

#include <limits>
#include <thread>

namespace swoole {

static bool size_mul_overflow(size_t a, size_t b, size_t *result) {
    if (a != 0 && b > std::numeric_limits<size_t>::max() / a) {
        return true;
    }
    *result = a * b;
    return false;
}

static bool size_add_overflow(size_t a, size_t b, size_t *result) {
    if (b > std::numeric_limits<size_t>::max() - a) {
        return true;
    }
    *result = a + b;
    return false;
}

Table *Table::make(uint32_t rows_size, float conflict_proportion) {
    if (rows_size >= SW_TABLE_MAX_ROW_SIZE) {
        rows_size = SW_TABLE_MAX_ROW_SIZE;
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

    auto table = static_cast<Table *>(sw_mem_pool()->alloc(sizeof(Table)));
    if (table == nullptr) {
        return nullptr;
    }
    table->mutex = new Mutex(true);
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

bool Table::add_column(const std::string &_name, enum TableColumn::Type _type, size_t _size) {
    if (created) {
        swoole_warning("unable to add column after table has been created");
        return false;
    }
    if (_type < TableColumn::TYPE_INT || _type > TableColumn::TYPE_STRING) {
        swoole_warning("unknown column type");
        return false;
    }
    if (column_map->find(_name) != column_map->end()) {
        swoole_warning("column[%s] already exists", _name.c_str());
        return false;
    }
    if (_type == TableColumn::TYPE_STRING && _size > std::numeric_limits<uint32_t>::max() - sizeof(TableStringLength)) {
        swoole_warning("column[%s] size is too large", _name.c_str());
        return false;
    }

    auto col = new TableColumn(_name, _type, _size);
    if (col->size > std::numeric_limits<size_t>::max() - item_size) {
        delete col;
        swoole_warning("table row size overflow");
        return false;
    }
    col->index = item_size;
    item_size += col->size;
    column_map->emplace(_name, col);
    column_list->push_back(col);

    return true;
}

TableColumn *Table::get_column(const std::string &key) const {
    auto i = column_map->find(key);
    if (i == column_map->end()) {
        return nullptr;
    } else {
        return i->second;
    }
}

bool Table::exists(const char *key, size_t keylen) const {
    TableRow *_rowlock = nullptr;
    const TableRow *row = get(key, keylen, &_rowlock);
    if (_rowlock) {
        _rowlock->unlock();
    }
    return row != nullptr;
}

TableIterator::TableIterator(size_t row_size) {
    current_ = (TableRow *) sw_malloc(row_size);
    if (!current_) {
        throw std::bad_alloc();
    }
    mutex_ = new Mutex(true);
    row_memory_size_ = row_size;
    reset();
}

void TableIterator::reset() {
    absolute_index = 0;
    collision_index = 0;
    sw_memset_zero(current_, row_memory_size_);
}

TableIterator::~TableIterator() {
    if (current_) {
        sw_free(current_);
    }
    delete mutex_;
}

size_t Table::calc_memory_size() const {
    /**
     * table size + conflict size
     */
    size_t conflict_row_num = size * conflict_proportion;
    size_t _row_num = 0;
    if (size_add_overflow(size, conflict_row_num, &_row_num)) {
        swoole_warning("table row number overflow");
        return 0;
    }

    /*
     * header + data
     */
    size_t _row_memory_size = 0;
    if (size_add_overflow(sizeof(TableRow), item_size, &_row_memory_size)) {
        swoole_warning("table row memory size overflow");
        return 0;
    }
    _row_memory_size = SW_MEM_ALIGNED_SIZE(_row_memory_size);

    /**
     * row data & header
     */
    size_t _memory_size = 0;
    if (size_mul_overflow(_row_num, _row_memory_size, &_memory_size)) {
        swoole_warning("table memory size overflow");
        return 0;
    }

    /**
     * memory pool for conflict rows
     */
    size_t conflict_pool_size = 0;
    if (size_mul_overflow(_row_num - size, FixedPool::sizeof_struct_slice(), &conflict_pool_size) ||
        size_add_overflow(conflict_pool_size, FixedPool::sizeof_struct_impl(), &conflict_pool_size) ||
        size_add_overflow(_memory_size, conflict_pool_size, &_memory_size)) {
        swoole_warning("table conflict pool memory size overflow");
        return 0;
    }

    /**
     * for iterator, Iterate through all the elements
     */
    size_t rows_index_size = 0;
    if (size_mul_overflow(size, sizeof(TableRow *), &rows_index_size) ||
        size_add_overflow(_memory_size, rows_index_size, &_memory_size)) {
        swoole_warning("table rows index memory size overflow");
        return 0;
    }

    swoole_trace("_memory_size=%lu, _row_num=%lu, _row_memory_size=%lu", _memory_size, _row_num, _row_memory_size);

    return _memory_size;
}

size_t Table::get_memory_size() const {
    return memory_size;
}

uint32_t Table::get_available_slice_num() const {
    lock();
    uint32_t num = pool->get_number_of_spare_slice();
    unlock();
    return num;
}

uint32_t Table::get_total_slice_num() const {
    return pool->get_number_of_total_slice();
}

bool Table::create() {
    if (created) {
        return false;
    }

    size_t _memory_size = calc_memory_size();
    if (_memory_size == 0) {
        return false;
    }
    const size_t _total_memory_size = _memory_size;
    size_t _row_memory_size = SW_MEM_ALIGNED_SIZE(sizeof(TableRow) + item_size);
    if (_row_memory_size > std::numeric_limits<uint32_t>::max()) {
        swoole_warning("table row memory size is too large");
        return false;
    }

    void *_memory = sw_shm_malloc(_memory_size);
    if (_memory == nullptr) {
        return false;
    }
    memory = _memory;

    rows = static_cast<TableRow **>(_memory);
    _memory = static_cast<char *>(_memory) + size * sizeof(TableRow *);
    _memory_size -= size * sizeof(TableRow *);

    for (size_t i = 0; i < size; i++) {
        rows[i] = reinterpret_cast<TableRow *>(static_cast<char *>(_memory) + (_row_memory_size * i));
        memset(rows[i], 0, sizeof(TableRow));
    }

    _memory = static_cast<char *>(_memory) + _row_memory_size * size;
    _memory_size -= _row_memory_size * size;
    pool = new FixedPool(static_cast<uint32_t>(_row_memory_size), _memory, _memory_size, true);
    iterator = new TableIterator(_row_memory_size);
    memory_size = _total_memory_size;
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
    delete iterator;
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

    while (true) {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1)) {
        _success:
            lock_pid = getpid();
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
        if (sw_kill(lock_pid, 0) < 0 && errno == ESRCH) {
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
        std::this_thread::yield();
    }
}

void Table::forward() const {
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

TableRow *Table::get(const char *key, size_t keylen, TableRow **rowlock) const {
    if (rowlock) {
        *rowlock = nullptr;
    }
    if (!is_valid_key_length(keylen)) {
        return nullptr;
    }

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

TableRow *Table::set(const char *key, size_t keylen, TableRow **rowlock, int *out_flags) {
    if (rowlock) {
        *rowlock = nullptr;
    }
    if (out_flags) {
        *out_flags = 0;
    }
    if (!is_valid_key_length(keylen)) {
        return nullptr;
    }

    TableRow *row = hash(key, keylen);
    *rowlock = row;
    row->lock();
    int _out_flags = 0;

    if (row->active) {
        uint32_t _conflict_level = 1;
        while (!sw_mem_equal(row->key, row->key_len, key, keylen)) {
            if (row->next == nullptr) {
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

bool Table::del(const char *key, size_t keylen) {
    if (!is_valid_key_length(keylen)) {
        return false;
    }

    TableRow *row = hash(key, keylen);
    TableRow *tmp, *prev = nullptr;

    row->lock();
    if (!row->active) {
        row->unlock();
        return false;
    }
    if (row->next == nullptr) {
        if (sw_mem_equal(row->key, row->key_len, key, keylen)) {
            row->clear();
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

    sw_atomic_fetch_add(&(delete_count), 1);
    sw_atomic_fetch_sub(&(row_num), 1);
    row->unlock();

    return true;
}

TableColumn::TableColumn(const std::string &_name, Type _type, size_t _size) {
    index = 0;
    name = _name;
    type = _type;
    switch (_type) {
    case TYPE_INT:
        size = sizeof(long);
        break;
    case TYPE_FLOAT:
        size = sizeof(double);
        break;
    case TYPE_STRING:
        size = _size + sizeof(TableStringLength);
        break;
    default:
        abort();
        break;
    }
}

void TableColumn::clear(TableRow *row) const {
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

void TableRow::set_value(const TableColumn *col, const void *value, size_t vlen) {
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

void TableRow::get_value(const TableColumn *col, double *dval) const {
    memcpy(dval, data + col->index, sizeof(*dval));
}

void TableRow::get_value(const TableColumn *col, long *lval) const {
    memcpy(lval, data + col->index, sizeof(*lval));
}

void TableRow::get_value(const TableColumn *col, char **value, TableStringLength *len) {
    memcpy(len, data + col->index, sizeof(*len));
    *value = data + col->index + sizeof(*len);
}

}  // namespace swoole

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

#pragma once

#include "swoole.h"
#include "swoole_memory.h"
#include "swoole_util.h"
#include "swoole_lock.h"
#include "swoole_hash.h"

#include <signal.h>

#include <vector>
#include <unordered_map>

//#define SW_TABLE_DEBUG   0
#define SW_TABLE_FORCE_UNLOCK_TIME 2000  // milliseconds
#define SW_TABLE_USE_PHP_HASH

namespace swoole {

typedef uint32_t TableStringLength;
typedef uint64_t (*HashFunc)(const char *key, size_t len);

struct TableColumn;

struct TableRow {
    sw_atomic_t lock_;
    pid_t lock_pid;
    /**
     * 1:used, 0:empty
     */
    uint8_t active;
    uint8_t key_len;
    /**
     * next slot
     */
    TableRow *next;
    /**
     * Hash Key
     */
    char key[SW_TABLE_KEY_SIZE];
    char data[0];

    void lock();

    void unlock() {
        sw_spinlock_release(&lock_);
    }

    void clear() {
        sw_memset_zero((char *) &lock_pid, sizeof(TableRow) - offsetof(TableRow, lock_pid));
    }

    void set_value(TableColumn *col, void *value, size_t vlen);
    void get_value(TableColumn *col, double *dval);
    void get_value(TableColumn *col, long *lval);
    void get_value(TableColumn *col, char **strval, TableStringLength *strlen);
};

struct TableIterator {
    size_t row_memory_size_;
    uint32_t absolute_index;
    uint32_t collision_index;
    TableRow *current_;
    Mutex *mutex_;

    TableIterator(size_t row_size) {
        current_ = (TableRow *) sw_malloc(row_size);
        if (!current_) {
            throw std::bad_alloc();
        }
        mutex_ = new Mutex(Mutex::PROCESS_SHARED);
        row_memory_size_ = row_size;
        reset();
    }

    void lock() {
        mutex_->lock();
    }

    void unlock() {
        mutex_->unlock();
    }

    void reset() {
        absolute_index = 0;
        collision_index = 0;
        sw_memset_zero(current_, row_memory_size_);
    }

    ~TableIterator() {
        if (current_) {
            sw_free(current_);
        }
        delete mutex_;
    }
};

enum TableFlag {
    SW_TABLE_FLAG_NEW_ROW = 1,
    SW_TABLE_FLAG_CONFLICT = 1u << 1,
};

struct TableColumn {
    enum Type {
        TYPE_INT = 1,
        TYPE_FLOAT,
        TYPE_STRING,
    };

    enum Type type;
    uint32_t size;
    std::string name;
    size_t index;

    TableColumn(const std::string &_name, enum Type _type, size_t _size) {
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

    void clear(TableRow *row);
};

class Table {
  private:
    Table() = delete;
    ~Table() = delete;

    std::unordered_map<std::string, TableColumn *> *column_map;
    Mutex *mutex;
    size_t size;
    size_t mask;
    size_t item_size;
    size_t memory_size;
    float conflict_proportion;

    /**
     * total rows that in active state(shm)
     */
    sw_atomic_t row_num;

    TableRow **rows;
    FixedPool *pool;

    TableIterator *iterator;
    HashFunc hash_func;
    bool created;

    void *memory;

  public:
    std::vector<TableColumn *> *column_list;

    size_t conflict_count;
    sw_atomic_long_t insert_count;
    sw_atomic_long_t delete_count;
    sw_atomic_long_t update_count;
    uint32_t conflict_max_level;

    static Table *make(uint32_t rows_size, float conflict_proportion);
    size_t calc_memory_size();
    size_t get_memory_size();
    uint32_t get_available_slice_num();
    uint32_t get_total_slice_num();
    bool create();
    bool add_column(const std::string &name, enum TableColumn::Type type, size_t size);
    TableRow *set(const char *key, uint16_t keylen, TableRow **rowlock, int *out_flags);
    TableRow *get(const char *key, uint16_t keylen, TableRow **rowlock);
    bool del(const char *key, uint16_t keylen);
    void forward();
    // only release local memory of the current process
    void free();
    // release shared memory
    void destroy();

    bool is_created() {
        return created;
    }

    bool ready() {
        return memory != nullptr;
    }

    void set_hash_func(HashFunc _fn) {
        hash_func = _fn;
    }

    size_t get_size() {
        return size;
    }

    TableRow *get_by_index(uint32_t index) {
        TableRow *row = rows[index];
        return row->active ? row : nullptr;
    }

    TableColumn *get_column(const std::string &key) {
        auto i = column_map->find(key);
        if (i == column_map->end()) {
            return nullptr;
        } else {
            return i->second;
        }
    }

    size_t count() {
        return row_num;
    }

    bool exists(const char *key, uint16_t keylen) {
        TableRow *_rowlock = nullptr;
        const TableRow *row = get(key, keylen, &_rowlock);
        _rowlock->unlock();
        return row != nullptr;
    }

    bool exists(const std::string &key) {
        return exists(key.c_str(), key.length());
    }

    TableRow *current() {
        return iterator->current_;
    }

    void rewind() {
        iterator->lock();
        iterator->reset();
        iterator->unlock();
    }

    void clear_row(TableRow *row) {
        for (auto i = column_list->begin(); i != column_list->end(); i++) {
            (*i)->clear(row);
        }
    }

  private:

    TableRow *hash(const char *key, int keylen) {
        uint64_t hashv = hash_func(key, keylen);
        uint64_t index = hashv & mask;
        assert(index < size);
        return rows[index];
    }

    TableRow *alloc_row() {
        lock();
        TableRow *new_row = (TableRow *) pool->alloc(0);
        unlock();
        return new_row;
    }

    void free_row(TableRow *tmp) {
        lock();
        tmp->clear();
        pool->free(tmp);
        unlock();
    }

    void check_key_length(uint16_t *keylen) {
        if (*keylen >= SW_TABLE_KEY_SIZE) {
            *keylen = SW_TABLE_KEY_SIZE - 1;
        }
    }

    void init_row(TableRow *new_row, const char *key, int keylen) {
        sw_memset_zero((char *) new_row + offsetof(TableRow, active), sizeof(TableRow) - offsetof(TableRow, active));
        memcpy(new_row->key, key, keylen);
        new_row->key[keylen] = '\0';
        new_row->key_len = keylen;
        new_row->active = 1;
        sw_atomic_fetch_add(&(row_num), 1);
    }

    int lock() {
        return mutex->lock();
    }

    int unlock() {
        return mutex->unlock();
    }
};
}  // namespace swoole

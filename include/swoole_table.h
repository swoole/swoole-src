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

#include "swoole.h"
#include "swoole_memory.h"
#include "swoole_util.h"
#include "swoole_log.h"
#include "swoole_lock.h"
#include "swoole_atomic.h"
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
};

struct TableIterator {
    uint32_t absolute_index;
    uint32_t collision_index;
    TableRow *row;
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

    TableRow **rows;
    swMemoryPool *pool;

    TableIterator *iterator;
    HashFunc hash_func;
    pid_t create_pid;

    void *memory;

#ifdef SW_TABLE_DEBUG
    int conflict_count;
    int insert_count;
    int conflict_max_level;
#endif

 public:
    std::vector<TableColumn *> *column_list;

    static Table *make(uint32_t rows_size, float conflict_proportion);
    size_t get_memory_size();
    bool create();
    bool is_created() {
        return memory != nullptr;
    }
    void set_hash_func(HashFunc _fn) {
        hash_func = _fn;
    }
    size_t get_size() {
        return size;
    }
    bool add_column(const std::string &name, enum TableColumn::Type type, size_t size);
    TableRow *set(const char *key, uint16_t keylen, TableRow **rowlock, int *out_flags);
    TableRow *get(const char *key, uint16_t keylen, TableRow **rowlock);
    bool del(const char *key, uint16_t keylen);
    void forward();
    void destroy();

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

    TableRow *current() {
        return iterator->row;
    }

    void rewind() {
        sw_memset_zero(iterator, sizeof(*iterator));
    }

    TableRow *hash(const char *key, int keylen) {
        uint64_t hashv = hash_func(key, keylen);
        uint64_t index = hashv & mask;
        assert(index < size);
        return rows[index];
    }

    void check_key_length(uint16_t *keylen) {
        if (*keylen >= SW_TABLE_KEY_SIZE) {
            *keylen = SW_TABLE_KEY_SIZE - 1;
        }
    }

    void init_row(TableRow *new_row, const char *key, int keylen) {
        sw_memset_zero(new_row, sizeof(TableRow));
        memcpy(new_row->key, key, keylen);
        new_row->key[keylen] = '\0';
        new_row->key_len = keylen;
        new_row->active = 1;
        sw_atomic_fetch_add(&(row_num), 1);
#ifdef SW_TABLE_DEBUG
        insert_count++;
#endif
    }
};
}

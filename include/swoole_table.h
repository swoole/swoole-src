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

typedef uint32_t swTable_string_length_t;

struct swTableRow {
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

struct swTable_iterator {
    uint32_t absolute_index;
    uint32_t collision_index;
    swTableRow *row;
};

enum swTableColumn_type {
    SW_TABLE_INT = 1,
    SW_TABLE_FLOAT,
    SW_TABLE_STRING,
};

enum swTable_flag {
    SW_TABLE_FLAG_NEW_ROW = 1,
    SW_TABLE_FLAG_CONFLICT = 1u << 1,
};

struct swTableColumn {
    enum swTableColumn_type type;
    uint32_t size;
    std::string name;
    size_t index;

    swTableColumn(const std::string &_name, enum swTableColumn_type _type, size_t _size) {
        index = 0;
        name = _name;
        type = _type;
        switch (_type) {
        case SW_TABLE_INT:
            size = sizeof(long);
            break;
        case SW_TABLE_FLOAT:
            size = sizeof(double);
            break;
        case SW_TABLE_STRING:
            size = _size + sizeof(swTable_string_length_t);
            break;
        default:
            abort();
            break;
        }
    }

    void clear(swTableRow *row);
};

struct swTable {
    std::unordered_map<std::string, swTableColumn *> *column_map;
    std::vector<swTableColumn *> *column_list;
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
    pid_t create_pid;

    void *memory;

#ifdef SW_TABLE_DEBUG
    int conflict_count;
    int insert_count;
    int conflict_max_level;
#endif
};

swTable *swTable_new(uint32_t rows_size, float conflict_proportion);
size_t swTable_get_memory_size(swTable *table);
int swTable_create(swTable *table);
void swTable_free(swTable *table);
bool swTableColumn_add(swTable *table, const std::string &name, enum swTableColumn_type type, size_t size);
swTableRow *swTableRow_set(swTable *table, const char *key, uint16_t keylen, swTableRow **rowlock, int *out_flags);
swTableRow *swTableRow_get(swTable *table, const char *key, uint16_t keylen, swTableRow **rowlock);

void swTable_iterator_rewind(swTable *table);
swTableRow *swTable_iterator_current(swTable *table);
void swTable_iterator_forward(swTable *table);
int swTableRow_del(swTable *table, const char *key, uint16_t keylen);

static inline swTableColumn *swTableColumn_get(swTable *table, const std::string &key) {
    auto i = table->column_map->find(key);
    if (i == table->column_map->end()) {
        return nullptr;
    } else {
        return i->second;
    }
}

#define SW_TABLE_FORCE_UNLOCK_TIME 2000  // milliseconds

static inline void swTableRow_lock(swTableRow *row) {
    sw_atomic_t *lock = &row->lock;
    uint32_t i, n;
    long t = 0;

    while (1) {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1)) {
        _success:
            row->lock_pid = SwooleG.pid;
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
        if (kill(row->lock_pid, 0) < 0 && errno == ESRCH) {
            *lock = 1;
            swWarn("lock process[%d] not exists, force unlock", row->lock_pid);
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
            swWarn("timeout, force unlock");
            goto _success;
        }
        sw_yield();
    }
}

static inline void swTableRow_unlock(swTableRow *row) {
    sw_spinlock_release(&row->lock);
}

static inline void swTableRow_clear(swTableRow *row) {
    sw_memset_zero((char *)row + offsetof(swTableRow, lock_pid), sizeof(swTableRow) - offsetof(swTableRow, lock_pid));
}

static inline void swTableRow_set_value(swTableRow *row, swTableColumn *col, void *value, size_t vlen) {
    switch (col->type) {
    case SW_TABLE_INT:
        memcpy(row->data + col->index, value, sizeof(long));
        break;
    case SW_TABLE_FLOAT:
        memcpy(row->data + col->index, value, sizeof(double));
        break;
    default:
        if (vlen > (col->size - sizeof(swTable_string_length_t))) {
            swWarn("[key=%s,field=%s]string value is too long", row->key, col->name.c_str());
            vlen = col->size - sizeof(swTable_string_length_t);
        }
        if (value == nullptr) {
            vlen = 0;
        }
        memcpy(row->data + col->index, &vlen, sizeof(swTable_string_length_t));
        if (vlen > 0) {
            memcpy(row->data + col->index + sizeof(swTable_string_length_t), value, vlen);
        }
        break;
    }
}

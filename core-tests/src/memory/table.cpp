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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_table.h"

using namespace swoole;

#include <exception>
#include <map>

struct exception_t : public std::exception {
    int code;
    std::string msg;
    exception_t(std::string _msg, int _code) : std::exception() {
        msg = _msg;
        code = _code;
    }
    const char *what() const throw() {
        return msg.c_str();
    }
};

struct row_t {
    std::string name;
    long id;
    double score;
};

class table_t {
  private:
    TableColumn *column_id;
    TableColumn *column_name;
    TableColumn *column_score;

    Table *table;

  public:
    table_t(uint32_t rows_size, float conflict_proportion = 0.2) {
        table = Table::make(rows_size, conflict_proportion);
        if (!table) {
            throw exception_t("alloc failed", swoole_get_last_error());
        }

        EXPECT_TRUE(table->add_column("id", TableColumn::TYPE_INT, 0));
        EXPECT_TRUE(table->add_column("name", TableColumn::TYPE_STRING, 32));
        EXPECT_TRUE(table->add_column("score", TableColumn::TYPE_FLOAT, 0));

        if (!table->create()) {
            throw exception_t("create failed", swoole_get_last_error());
        }
        column_id = table->get_column("id");
        column_name = table->get_column("name");
        column_score = table->get_column("score");
    }

    bool set(const std::string &key, const row_t &value) {
        TableRow *_rowlock = nullptr;
        TableRow *row = table->set(key.c_str(), key.length(), &_rowlock, nullptr);
        if (!row) {
            _rowlock->unlock();
            return false;
        }

        row->set_value(column_id, (void *) &value.id, sizeof(value.id));
        row->set_value(column_name, (void *) value.name.c_str(), value.name.length());
        row->set_value(column_score, (void *) &value.score, sizeof(value.score));

        _rowlock->unlock();

        return true;
    }

    row_t get(const std::string &key) {
        row_t result;
        TableRow *_rowlock = nullptr;
        TableRow *row = table->get(key.c_str(), key.length(), &_rowlock);
        if (row) {
            memcpy(&result.id, row->data + column_id->index, sizeof(result.id));
            memcpy(&result.score, row->data + column_score->index, sizeof(result.score));

            TableStringLength l;
            memcpy(&l, row->data + column_name->index, sizeof(l));
            result.name = std::string(row->data + column_name->index + sizeof(l), l);
        }
        _rowlock->unlock();

        return result;
    }

    bool del(const std::string &key) {
        return table->del(key.c_str(), key.length());
    }

    bool exists(const std::string &key) {
        TableRow *_rowlock = nullptr;
        TableRow *row = table->get(key.c_str(), key.length(), &_rowlock);
        _rowlock->unlock();

        return row != nullptr;
    }

    size_t count() {
        return table->count();
    }

    Table *ptr() {
        return table;
    }

    ~table_t() {
        if (table) {
            table->destroy();
        }
    }
};

TEST(table, create) {
    table_t table(1024);
    auto ptr = table.ptr();

    ASSERT_GT(ptr->get_memory_size(), ptr->get_size() * ptr->get_column_size());

    ASSERT_FALSE(ptr->create());  // create again should fail

    ASSERT_TRUE(table.set("php", {"php", 1, 1.245}));
    ASSERT_TRUE(table.set("java", {"java", 2, 3.1415926}));
    ASSERT_TRUE(table.set("c++", {"c++", 3, 4.888}));

    ASSERT_EQ(table.count(), 3);

    row_t r1 = table.get("java");
    ASSERT_EQ(r1.id, 2);
    ASSERT_EQ(r1.score, 3.1415926);
    ASSERT_EQ(r1.name, std::string("java"));

    ASSERT_FALSE(ptr->get_column("not-exists"));

    ASSERT_TRUE(table.exists("php"));
    ASSERT_TRUE(table.del("php"));
    ASSERT_FALSE(table.exists("php"));

    ASSERT_FALSE(table.del("not-exists"));

    // Test with a string that is longer than the column size
    ASSERT_TRUE(table.set("golang", {"golang " TEST_JPG_MD5SUM TEST_JPG_MD5SUM, 3, 4.888}));
}

void start_iterator(Table *_ptr) {
    _ptr->rewind();
    auto count = 0;
    while (true) {
        _ptr->forward();
        auto row = _ptr->current();
        if (row->key_len == 0) {
            break;
        }
        ASSERT_TRUE(_ptr->exists(row->key, row->key_len));
        count++;
    }
    ASSERT_EQ(count, _ptr->count());
}

TEST(table, iterator) {
    table_t table(1024);

    table.set("php", {"php", 1, 1.245});
    table.set("java", {"java", 2, 3.1415926});
    table.set("c++", {"c++", 3, 4.888});

    auto _ptr = table.ptr();
    start_iterator(_ptr);
}

TEST(table, iterator_2) {
    table_t table(1024);
    auto _ptr = table.ptr();
    _ptr->set_hash_func([](const char *key, size_t len) -> uint64_t { return 1; });

    table.set("php", {"php", 1, 1.245});
    table.set("java", {"java", 2, 3.1415926});
    table.set("c++", {"c++", 3, 4.888});

    start_iterator(_ptr);
}

static int test_table_size = 128;

static void create_table(table_t &table) {
    auto ptr = table.ptr();
    ptr->set_hash_func([](const char *key, size_t len) -> uint64_t { return 1; });

    ASSERT_TRUE(table.set("php", {"php", 1, 1.245}));
    ASSERT_TRUE(table.set("java", {"java", 2, 3.1415926}));
    ASSERT_TRUE(table.set("c++", {"c++", 3, 4.888}));
    ASSERT_TRUE(table.set("js", {"js", 9, 6565}));
    ASSERT_TRUE(table.set("golang", {"golang", 4, 9.888}));
}

TEST(table, conflict1) {
    table_t table(test_table_size);
    ASSERT_FALSE(table.exists("swift"));

    create_table(table);
    auto ptr = table.ptr();

    ASSERT_FALSE(table.exists("kotlin"));

    ASSERT_TRUE(table.del("php"));
    ASSERT_FALSE(table.exists("php"));
    ASSERT_TRUE(table.set("rust", {"rust", 5, 9.888}));

    ASSERT_TRUE(table.del("golang"));
    ASSERT_FALSE(table.exists("golang"));
    ASSERT_TRUE(table.set("erlang", {"erlang", 6, 12.888}));

    ASSERT_TRUE(table.del("java"));
    ASSERT_FALSE(table.exists("java"));

    ASSERT_EQ(ptr->get_total_slice_num() - ptr->get_available_slice_num(), table.count() - 1);
}

TEST(table, conflict2) {
    table_t table(test_table_size);
    create_table(table);
    auto ptr = table.ptr();

    ASSERT_TRUE(table.del("java"));
    ASSERT_FALSE(table.exists("java"));
    ASSERT_TRUE(table.set("rust", {"rust", 5, 9.888}));

    ASSERT_TRUE(table.del("golang"));
    ASSERT_FALSE(table.exists("golang"));
    ASSERT_TRUE(table.set("erlang", {"erlang", 6, 12.888}));

    ASSERT_EQ(ptr->get_total_slice_num() - ptr->get_available_slice_num(), table.count() - 1);
}

TEST(table, conflict3) {
    table_t table(test_table_size);
    create_table(table);
    auto ptr = table.ptr();

    ASSERT_TRUE(table.del("golang"));
    ASSERT_TRUE(table.set("erlang", {"erlang", 6, 12.888}));

    ASSERT_TRUE(table.del("java"));

    ASSERT_EQ(ptr->get_total_slice_num() - ptr->get_available_slice_num(), table.count() - 1);
}

TEST(table, conflict4) {
    table_t table(test_table_size);
    create_table(table);
    auto ptr = table.ptr();

    ASSERT_TRUE(table.del("c++"));
    ASSERT_TRUE(table.set("rust", {"rust", 5, 9.888}));

    ASSERT_TRUE(table.del("golang"));
    ASSERT_TRUE(table.set("erlang", {"erlang", 6, 12.888}));

    ASSERT_TRUE(table.del("java"));

    ASSERT_EQ(ptr->get_total_slice_num() - ptr->get_available_slice_num(), table.count() - 1);
}

TEST(table, get_value) {
    table_t table(test_table_size);
    create_table(table);
    auto ptr = table.ptr();

    std::string key("php");
    TableRow *_rowlock = nullptr;
    TableRow *row = ptr->get(key.c_str(), key.length(), &_rowlock);
    _rowlock->unlock();
    TableColumn *column_id = ptr->get_column("id");
    TableColumn *column_name = ptr->get_column("name");
    TableColumn *column_score = ptr->get_column("score");

    char *str = nullptr;
    TableStringLength len = 0;
    row->get_value(column_name, &str, &len);
    ASSERT_STREQ(str, "php");

    double dval = 0;
    row->get_value(column_score, &dval);
    ASSERT_EQ(dval, 1.245);

    long lval = 0;
    row->get_value(column_id, &lval);
    ASSERT_EQ(lval, 1);

    column_id->clear(row);
    column_name->clear(row);
    column_score->clear(row);

    row->get_value(column_name, &str, &len);
    ASSERT_STREQ(str, "php");

    row->get_value(column_score, &dval);
    ASSERT_EQ(dval, 0);

    row->get_value(column_id, &lval);
    ASSERT_EQ(lval, 0);
}

TEST(table, lock) {
    table_t table(test_table_size);
    create_table(table);
    auto ptr = table.ptr();

    std::string key("php");
    TableRow *_rowlock = nullptr;

    for (int i = 0; i <= 3; i++) {
        std::thread t([&]() {
            TableRow *row = ptr->get(key.c_str(), key.length(), &_rowlock);
            TableColumn *column_name = ptr->get_column("name");
            char *str = nullptr;
            TableStringLength len = 0;
            row->get_value(column_name, &str, &len);
            ASSERT_STREQ(str, "php");
        });
        t.join();
    }
    _rowlock->unlock();
}

TEST(table, size_limit) {
    auto t1 = Table::make(0x90000000, 1.2);
    ASSERT_EQ(t1->get_size(), SW_TABLE_MAX_ROW_SIZE);
    ASSERT_EQ(t1->get_conflict_proportion(), 1.0);

    EXPECT_FALSE(t1->add_column("bad_field", (TableColumn::Type) 8, 0));

    auto t2 = Table::make(1024, 0.1);
    ASSERT_EQ(t2->get_size(), 1024);
    ASSERT_EQ(t2->get_conflict_proportion(), (float) SW_TABLE_CONFLICT_PROPORTION);
}

TEST(table, lock_crash) {
    table_t table(test_table_size);
    create_table(table);
    auto ptr = table.ptr();

    auto child = test::spawn_exec([ptr]() {
        TableRow *_rowlock = nullptr;
        ptr->get("java", 4, &_rowlock);
        usleep(5);
        exit(200);  // Simulate a crash in the child process, no release lock
    });
    ASSERT_GT(child, 0);
    test::wait_all_child_processes();

    TableRow *_rowlock = nullptr;
    ASSERT_NE(ptr->get("java", 4, &_rowlock), nullptr);
    _rowlock->unlock();
}

TEST(table, lock_race) {
    table_t table(test_table_size);
    create_table(table);
    auto ptr = table.ptr();

    auto child = test::spawn_exec([ptr]() {
        TableRow *_rowlock = nullptr;
        ASSERT_NE(ptr->get("java", 4, &_rowlock), nullptr);
        usleep(5);
        _rowlock->unlock();
    });
    ASSERT_GT(child, 0);

    TableRow *_rowlock = nullptr;
    ASSERT_NE(ptr->get("java", 4, &_rowlock), nullptr);
    _rowlock->unlock();

    test::wait_all_child_processes();
}

TEST(table, exhaustion) {
    table_t table(4, 1.0);
    auto ptr = table.ptr();
    // All keys hash to same bucket — deterministic collision chain
    ptr->set_hash_func([](const char *key, size_t len) -> uint64_t { return 1; });

    // Capacity: 1 static row + N conflict slices
    size_t capacity = 1 + ptr->get_total_slice_num();
    ASSERT_GT(capacity, 1);

    for (size_t i = 0; i < capacity; i++) {
        char key[16];
        snprintf(key, sizeof(key), "k%zu", i);
        ASSERT_TRUE(table.set(key, {key, (long) i, (double) i})) << "insert k" << i;
    }
    ASSERT_EQ(table.count(), capacity);
    ASSERT_EQ(ptr->get_available_slice_num(), 0);

    // Conflict pool exhausted — next set should fail
    ASSERT_FALSE(table.set("overflow", {"overflow", 999, 999.0}));

    // Delete the last conflict row (not the head) to free a FixedPool slice
    char last_key[16];
    snprintf(last_key, sizeof(last_key), "k%zu", capacity - 1);
    ASSERT_TRUE(table.del(last_key));
    ASSERT_EQ(ptr->get_available_slice_num(), 1);

    // Re-insert succeeds
    ASSERT_TRUE(table.set("new_key", {"new_key", 999, 999.0}));
    ASSERT_TRUE(table.exists("new_key"));
    ASSERT_EQ(table.count(), capacity);
}

TEST(table, collision_chain_ops) {
    table_t table(128);
    auto ptr = table.ptr();
    ptr->set_hash_func([](const char *key, size_t len) -> uint64_t { return 1; });

    // build chain: head + 5 collisions
    ASSERT_TRUE(table.set("k1", {"k1", 1, 1.0}));
    ASSERT_TRUE(table.set("k2", {"k2", 2, 2.0}));
    ASSERT_TRUE(table.set("k3", {"k3", 3, 3.0}));
    ASSERT_TRUE(table.set("k4", {"k4", 4, 4.0}));
    ASSERT_TRUE(table.set("k5", {"k5", 5, 5.0}));
    ASSERT_TRUE(table.set("k6", {"k6", 6, 6.0}));
    ASSERT_EQ(table.count(), 6);

    // delete middle element
    ASSERT_TRUE(table.del("k3"));
    ASSERT_FALSE(table.exists("k3"));
    ASSERT_EQ(table.count(), 5);

    // all other keys intact
    ASSERT_TRUE(table.exists("k1"));
    ASSERT_TRUE(table.exists("k2"));
    ASSERT_TRUE(table.exists("k4"));
    ASSERT_TRUE(table.exists("k5"));
    ASSERT_TRUE(table.exists("k6"));

    // delete head — triggers memcpy of k2 into head, then free k2's old slot
    ASSERT_TRUE(table.del("k1"));
    ASSERT_FALSE(table.exists("k1"));
    ASSERT_TRUE(table.exists("k2"));  // k2's data moved to head slot
    ASSERT_EQ(table.count(), 4);

    // delete tail
    ASSERT_TRUE(table.del("k6"));
    ASSERT_FALSE(table.exists("k6"));
    ASSERT_EQ(table.count(), 3);

    // remaining keys {k2, k4, k5} should be reachable via iteration
    ptr->rewind();
    int iter_count = 0;
    while (true) {
        ptr->forward();
        auto row = ptr->current();
        if (row->key_len == 0) break;
        ASSERT_TRUE(table.exists(std::string(row->key, row->key_len)));
        iter_count++;
    }
    ASSERT_EQ(iter_count, 3);
}

// Exercise all three FixedPool free() code paths after exhaustion.
//
// After exhaustion with hash-to-1, the FixedPool combined list is:
//   head → kN → kN-1 → ... → k1 ↔ k0 (static row)
//   tail = kN (last allocated, also at head)
//
// free() paths and how to trigger them from Table:
//   1. tail-branch: free the tail when it's NOT also the head
//      → free k(cap-2) first (moves head away), then free k(cap-1) (still tail)
//   2. else-branch (middle unlink): free an element between head and tail
//      → free k2 (somewhere in the middle)
//   3. early-return (head-branch): free the element at impl->head
//      → after the above frees reshuffle the list, free whatever is now at head
TEST(table, exhaustion_free_paths) {
    table_t table(4, 1.0);
    auto ptr = table.ptr();
    ptr->set_hash_func([](const char *key, size_t len) -> uint64_t { return 1; });

    size_t n_conflict = ptr->get_total_slice_num();
    size_t cap = 1 + n_conflict;
    ASSERT_GT(n_conflict, 3) << "need at least 4 conflict slices for this test";

    // fill to exhaustion
    for (size_t i = 0; i < cap; i++) {
        char key[16];
        snprintf(key, sizeof(key), "k%zu", i);
        ASSERT_TRUE(table.set(key, {key, (long) i, (double) i})) << "insert k" << i;
    }
    ASSERT_EQ(ptr->get_available_slice_num(), 0);

    // ---- path 1: tail-branch ----
    // Free a middle element first so head moves away, then free the tail.
    char a[16];
    snprintf(a, sizeof(a), "k%zu", cap - 2);
    ASSERT_TRUE(table.del(a));
    ASSERT_EQ(ptr->get_available_slice_num(), 1);

    // Now k(cap-1) is still the tail but no longer the head → tail-branch.
    char b[16];
    snprintf(b, sizeof(b), "k%zu", cap - 1);
    ASSERT_TRUE(table.del(b));
    ASSERT_EQ(ptr->get_available_slice_num(), 2);

    // ---- path 2: else-branch (middle unlink) ----
    // k1 is the first conflict row, somewhere in the middle of the busy chain.
    ASSERT_TRUE(table.del("k1"));
    ASSERT_EQ(ptr->get_available_slice_num(), 3);

    // ---- path 3: head-branch (early return) ----
    // After freeing two adjacent slices from the tail end, the current
    // impl->head may be one of the just-freed slices.  Deleting the next
    // adjacent key exercises whatever free() path is appropriate given the
    // current list state.
    char c[16];
    snprintf(c, sizeof(c), "k%zu", cap - 3);
    ASSERT_TRUE(table.del(c));
    ASSERT_EQ(ptr->get_available_slice_num(), 4);

    // all freed slots should be reusable
    ASSERT_TRUE(table.set("r1", {"r1", 100, 100.0}));
    ASSERT_TRUE(table.set("r2", {"r2", 200, 200.0}));
    ASSERT_TRUE(table.set("r3", {"r3", 300, 300.0}));
    ASSERT_TRUE(table.set("r4", {"r4", 400, 400.0}));

    // verify iteration count matches
    ptr->rewind();
    int count = 0;
    while (true) {
        ptr->forward();
        auto row = ptr->current();
        if (row->key_len == 0) break;
        count++;
    }
    ASSERT_EQ(count, cap);
}

// Drain all entries and refill — verifies FixedPool returns to consistent state
TEST(table, drain_and_refill) {
    table_t table(4, 1.0);
    auto ptr = table.ptr();
    ptr->set_hash_func([](const char *key, size_t len) -> uint64_t { return 1; });

    size_t cap = 1 + ptr->get_total_slice_num();

    // fill
    for (size_t i = 0; i < cap; i++) {
        char key[16];
        snprintf(key, sizeof(key), "k%zu", i);
        ASSERT_TRUE(table.set(key, {key, (long) i, (double) i}));
    }
    ASSERT_EQ(table.count(), cap);

    // drain all
    for (size_t i = 0; i < cap; i++) {
        char key[16];
        snprintf(key, sizeof(key), "k%zu", i);
        ASSERT_TRUE(table.del(key));
    }
    ASSERT_EQ(table.count(), 0);
    ASSERT_EQ(ptr->get_available_slice_num(), ptr->get_total_slice_num());

    // refill — every slot should be reusable
    for (size_t i = 0; i < cap; i++) {
        char key[16];
        snprintf(key, sizeof(key), "v%zu", i);
        ASSERT_TRUE(table.set(key, {key, (long) i + 1000, (double) i + 0.5})) << "refill v" << i;
    }
    ASSERT_EQ(table.count(), cap);

    // verify data
    row_t r = table.get("v0");
    ASSERT_EQ(r.id, 1000);
    ASSERT_DOUBLE_EQ(r.score, 0.5);

    // verify iteration
    ptr->rewind();
    int count = 0;
    while (true) {
        ptr->forward();
        auto row = ptr->current();
        if (row->key_len == 0) break;
        count++;
    }
    ASSERT_EQ(count, cap);
}
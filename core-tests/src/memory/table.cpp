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

        table->add_column("id", TableColumn::TYPE_INT, 0);
        table->add_column("name", TableColumn::TYPE_STRING, 32);
        table->add_column("score", TableColumn::TYPE_FLOAT, 0);

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

    table.set("php", {"php", 1, 1.245});
    table.set("java", {"java", 2, 3.1415926});
    table.set("c++", {"c++", 3, 4.888});

    ASSERT_EQ(table.count(), 3);

    row_t r1 = table.get("java");
    ASSERT_EQ(r1.id, 2);
    ASSERT_EQ(r1.score, 3.1415926);
    ASSERT_EQ(r1.name, std::string("java"));

    ASSERT_TRUE(table.exists("php"));
    ASSERT_TRUE(table.del("php"));
    ASSERT_FALSE(table.exists("php"));
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

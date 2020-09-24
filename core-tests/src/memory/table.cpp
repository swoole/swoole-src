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
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_table.h"

using namespace swoole;

#include <exception>

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
        return table->del(key.c_str(), key.length()) == SW_OK;
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

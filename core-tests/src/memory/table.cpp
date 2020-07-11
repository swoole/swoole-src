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

#include "tests.h"
#include "table.h"

#include <exception>

struct exception_t : public std::exception {
    int code;
    std::string msg;
    exception_t(std::string _msg, int _code) : std::exception() {
        msg = _msg;
        code = _code;
    }
    const char *what() const throw() { return msg.c_str(); }
};

struct row_t {
    std::string name;
    long id;
    double score;
};

class table_t {
   private:
    swTableColumn *column_id;
    swTableColumn *column_name;
    swTableColumn *column_score;

    swTable *table;

   public:
    table_t(uint32_t rows_size, float conflict_proportion = 0.2) {
        table = swTable_new(rows_size, conflict_proportion);
        if (swTable_create(table), 0) {
            throw exception_t("alloc failed", SwooleG.error);
        }

        swTableColumn_add(table, "id", SW_TABLE_INT, 0);
        swTableColumn_add(table, "name", SW_TABLE_STRING, 32);
        swTableColumn_add(table, "score", SW_TABLE_FLOAT, 0);

        if (swTable_create(table) < 0) {
            throw exception_t("create failed", SwooleG.error);
        }
        column_id = swTableColumn_get(table, std::string("id"));
        column_name = swTableColumn_get(table, std::string("name"));
        column_score = swTableColumn_get(table, std::string("score"));
    }

    bool set(const std::string &key, const row_t &value) {
        swTableRow *_rowlock = nullptr;
        swTableRow *row = swTableRow_set(table, key.c_str(), key.length(), &_rowlock);
        if (!row) {
            swTableRow_unlock(_rowlock);
            return false;
        }

        swTableRow_set_value(row, column_id, (void *) &value.id, sizeof(value.id));
        swTableRow_set_value(row, column_name, (void *) value.name.c_str(), value.name.length());
        swTableRow_set_value(row, column_score, (void *) &value.score, sizeof(value.score));

        swTableRow_unlock(_rowlock);

        return true;
    }

    row_t get(const std::string &key) {
        row_t result;
        swTableRow *_rowlock = nullptr;
        swTableRow *row = swTableRow_get(table, key.c_str(), key.length(), &_rowlock);
        if (row) {
            memcpy(&result.id, row->data + column_id->index, sizeof(result.id));
            memcpy(&result.score, row->data + column_score->index, sizeof(result.score));

            swTable_string_length_t l;
            memcpy(&l, row->data + column_name->index, sizeof(l));
            result.name = std::string(row->data + column_name->index + sizeof(l), l);
        }
        swTableRow_unlock(_rowlock);

        return result;
    }

    bool del(const std::string &key) { return swTableRow_del(table, key.c_str(), key.length()) == SW_OK; }

    bool exists(const std::string &key) {
        swTableRow *_rowlock = nullptr;
        swTableRow *row = swTableRow_get(table, key.c_str(), key.length(), &_rowlock);
        swTableRow_unlock(_rowlock);

        return row != nullptr;
    }

    size_t count() { return table->row_num; }

    ~table_t() {
        if (table) {
            swTable_free(table);
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

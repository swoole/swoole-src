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

#include "swoole_file.h"

using namespace swoole;

TEST(file, read_line) {
    std::string filename = test::get_root_path() + "/tests/include/bootstrap.php";
    File file(filename, File::READ);
    FILE *stdc_file = fopen(filename.c_str(), "r");
    ASSERT_NE(stdc_file, nullptr);
    char buf1[1024];
    char buf2[1024];

    size_t size = file.get_size();
    size_t total = 0;

    while(true) {
        auto retval = file.read_line(buf1, sizeof(buf1));
        if (retval == 0) {
            break;
        }
        total += retval;
        ASSERT_NE(fgets(buf2, sizeof(buf2), stdc_file), nullptr);
        ASSERT_STREQ(buf1, buf2);
    }
    ASSERT_EQ(total, size);
}

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
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_error.h"

#include <unordered_map>

using namespace swoole;
using namespace std;

TEST(error, errno_constants) {
    unordered_map<string, int> values;

    for (const auto *error = get_errno_constants(); error->name; error++) {
        ASSERT_TRUE(values.emplace(error->name, error->value).second);
    }

    ASSERT_EQ(values.at("EWOULDBLOCK"), values.at("EAGAIN"));
}

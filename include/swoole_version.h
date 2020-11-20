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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#ifndef SWOOLE_VERSION_H_
#define SWOOLE_VERSION_H_

#define SWOOLE_MAJOR_VERSION 4
#define SWOOLE_MINOR_VERSION 5
#define SWOOLE_RELEASE_VERSION 8
#define SWOOLE_EXTRA_VERSION ""
#define SWOOLE_VERSION "4.5.8"
#define SWOOLE_VERSION_ID 40508
#define SWOOLE_API_VERSION_ID 0x202011a

#define SWOOLE_BUG_REPORT                                                                                              \
    "A bug occurred in Swoole-v" SWOOLE_VERSION ", please report it.\n"                                                \
    "The Swoole developers probably don't know about it,\n"                                                            \
    "and unless you report it, chances are it won't be fixed.\n"                                                       \
    "You can read How to report a bug doc before submitting any bug reports:\n"                                        \
    ">> https://github.com/swoole/swoole-src/blob/master/.github/ISSUE.md \n"                                          \
    "Please do not send bug reports in the mailing list or personal letters.\n"                                        \
    "The issue page is also suitable to submit feature requests.\n"

#endif

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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#ifndef SWOOLE_VERSION_H_
#define SWOOLE_VERSION_H_

#define SWOOLE_MAJOR_VERSION <?=$next->major."\n" ?>
#define SWOOLE_MINOR_VERSION <?=$next->minor."\n" ?>
#define SWOOLE_RELEASE_VERSION <?=$next->release."\n" ?>
#define SWOOLE_EXTRA_VERSION "<?=$next->extra ?>"
#define SWOOLE_VERSION "<?=$next->getVersion() ?>"
#define SWOOLE_VERSION_ID <?=$next->getVersionId()."\n" ?>
#define SWOOLE_API_VERSION_ID <?=$next->api."\n" ?>

#define SWOOLE_BUG_REPORT                                                                                              \
    "A bug occurred in Swoole-v" SWOOLE_VERSION ", please report it.\n"                                                \
    "The Swoole developers probably don't know about it,\n"                                                            \
    "and unless you report it, chances are it won't be fixed.\n"                                                       \
    "You can read How to report a bug doc before submitting any bug reports:\n"                                        \
    ">> https://github.com/swoole/swoole-src/blob/master/.github/ISSUE.md \n"                                          \
    "Please do not send bug reports in the mailing list or personal letters.\n"                                        \
    "The issue page is also suitable to submit feature requests.\n"

#endif

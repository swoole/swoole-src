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
#if 0
#include "swoole.h"
#include "tests.h"
#include "websocket.h"

swUnitTest(ws_test1)
{
	char buf[65536];
	int fd = open("./websocket.log", O_RDONLY);
	int len = swoole_sync_readfile(fd, buf, 65536) ;
	if (len > 0)
	{
		swWebSocket_decode(buf);
	}
	return 0;
}
#endif
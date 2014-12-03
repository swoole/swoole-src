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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/


#ifndef	WEBSOCKET_BASE64_H_
#define	WEBSOCKET_BASE64_H_

#include "stdio.h"

int swBase64_encode(unsigned char **, size_t *, const unsigned char *, size_t);
int swBase64_decode(unsigned char **, size_t *, const unsigned char *);



#endif	/*WEBSOCKET_BASE64_H_ */


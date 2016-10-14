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

#ifndef SW_HTTP_H_
#define SW_HTTP_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <stdint.h>

enum swHttpMethod
{
    HTTP_DELETE = 1, HTTP_GET, HTTP_HEAD, HTTP_POST, HTTP_PUT, HTTP_PATCH,
    /* pathological */
    HTTP_CONNECT, HTTP_OPTIONS, HTTP_TRACE,
    /* webdav */
    HTTP_COPY, HTTP_LOCK, HTTP_MKCOL, HTTP_MOVE, HTTP_PROPFIND, HTTP_PROPPATCH, HTTP_UNLOCK,
    /* subversion */
    HTTP_REPORT, HTTP_MKACTIVITY, HTTP_CHECKOUT, HTTP_MERGE,
    /* upnp */
    HTTP_MSEARCH, HTTP_NOTIFY, HTTP_SUBSCRIBE, HTTP_UNSUBSCRIBE,
    /* Http2 */
    HTTP_PRI,
};

enum swHttpVersion
{
    HTTP_VERSION_10 = 1,
    HTTP_VERSION_11,
};

typedef struct _swHttpRequest
{
    uint8_t method;
    uint8_t offset;
    uint8_t version;
    uint8_t free_memory;

    uint32_t header_length;
    uint32_t content_length;

    swString *buffer;

    uint8_t opcode;

} swHttpRequest;

int swHttpRequest_get_protocol(swHttpRequest *request);
int swHttpRequest_get_content_length(swHttpRequest *request);
int swHttpRequest_get_header_length(swHttpRequest *request);
void swHttpRequest_free(swConnection *conn);
#ifdef SW_HTTP_100_CONTINUE
int swHttpRequest_has_expect_header(swHttpRequest *request);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SW_HTTP_H_ */

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

enum http_method
{
    HTTP_DELETE = 1, HTTP_GET, HTTP_HEAD, HTTP_POST, HTTP_PUT,
    /* pathological */
    HTTP_CONNECT, HTTP_OPTIONS, HTTP_TRACE,
    /* webdav */
    HTTP_COPY, HTTP_LOCK, HTTP_MKCOL, HTTP_MOVE, HTTP_PROPFIND, HTTP_PROPPATCH, HTTP_UNLOCK,
    /* subversion */
    HTTP_REPORT, HTTP_MKACTIVITY, HTTP_CHECKOUT, HTTP_MERGE,
    /* upnp */
    HTTP_MSEARCH, HTTP_NOTIFY, HTTP_SUBSCRIBE, HTTP_UNSUBSCRIBE,
};

/**
 * Compile with -DHTTP_PARSER_STRICT=0 to make less checks, but run faster
 */
#ifndef HTTP_PARSER_STRICT
# define HTTP_PARSER_STRICT 1
#else
# define HTTP_PARSER_STRICT 0
#endif

/* Maximium header size allowed */
#define HTTP_MAX_HEADER_SIZE (80*1024)

typedef struct http_parser http_parser;
typedef struct http_parser_settings http_parser_settings;

/* Callbacks should return non-zero to indicate an error. The parser will
 * then halt execution.
 *
 * The one exception is on_headers_complete. In a HTTP_RESPONSE parser
 * returning '1' from on_headers_complete will tell the parser that it
 * should not expect a body. This is used when receiving a response to a
 * HEAD request which may contain 'Content-Length' or 'Transfer-Encoding:
 * chunked' headers that indicate the presence of a body.
 *
 * http_data_cb does not return data chunks. It will be call arbitrarally
 * many times for each string. E.G. you might get 10 callbacks for "on_path"
 * each providing just a few characters more data.
 */
typedef int (*http_data_cb)(http_parser *, const char *at, size_t length);
typedef int (*http_cb)(http_parser *);

enum http_parser_type
{
	HTTP_REQUEST = 1,
	HTTP_RESPONSE,
	HTTP_BOTH,
};

enum http_version
{
    HTTP_VERSION_10 = 1,
    HTTP_VERSION_11,
};

struct http_parser
{
	/** PRIVATE **/
	unsigned char type :2;
	unsigned char flags :6;
	unsigned char state;
	unsigned char header_state;
	unsigned char index;

	uint32_t nread;
	int64_t content_length;

	/** READ-ONLY **/
	unsigned short http_major;
	unsigned short http_minor;
	unsigned short status_code; /* responses only */
	unsigned char method; /* requests only */

	/* 1 = Upgrade header was present and the parser has exited because of that.
	 * 0 = No upgrade header present.
	 * Should be checked when http_parser_execute() returns in addition to
	 * error checking.
	 */
	char upgrade;

	/** PUBLIC **/
	void *data; /* A pointer to get hook to the "connection" or "socket" object */
};


struct http_parser_settings
{
	http_cb on_message_begin;
	http_data_cb on_path;
	http_data_cb on_query_string;
	http_data_cb on_url;
	http_data_cb on_fragment;
	http_data_cb on_header_field;
	http_data_cb on_header_value;
	http_cb on_headers_complete;
	http_data_cb on_body;
	http_cb on_message_complete;
};


typedef struct _swHttpRequest
{
    uint8_t method;
    uint8_t version;
    uint8_t state;
    uint8_t free_memory;

    uint32_t header_length;
    uint32_t content_length;

    swString *buffer;

} swHttpRequest;

int swHttpRequest_get_protocol(swHttpRequest *request);
int swHttpRequest_get_content_length(swHttpRequest *request);
void swHttpRequest_free(swHttpRequest *request);

void http_parser_init(http_parser *parser, enum http_parser_type type);

size_t http_parser_execute(http_parser *parser, const http_parser_settings *settings, const char *data, size_t len);

/* If http_should_keep_alive() in the on_headers_complete or
 * on_message_complete callback returns true, then this will be should be
 * the last message on the connection.
 * If you are the server, respond with the "Connection: close" header.
 * If you are the client, close the connection.
 */
int http_should_keep_alive(http_parser *parser);

/* Returns a string version of the HTTP method. */
const char *http_method_str(enum http_method);

int http_parser_has_error(http_parser *parser);

#ifdef __cplusplus
}
#endif

#endif /* SW_HTTP_H_ */

/*
 * http.c
 *
 *  Created on: 2013-6-3
 *      Author: htf
 */

#include "swoole.h"
#include "tests.h"

#include "deps/php_http_parser/php_http_parser.h"

struct line
{
	char *field;
	size_t field_len;
	char *value;
	size_t value_len;
};

#define CURRENT_LINE (&header[nlines-1])
#define MAX_HEADER_LINES 2000

swUnitTest(http_test2)
{
	char *errstr;
	php_cli_server_client client;
	bzero(&client, sizeof(client));
	memcpy(client.buf, SW_STRL("GET / HTTP/1.1\r\n\
Host: www.baidu.com\r\n\
Connection: keep-alive\r\n\
Cache-Control: max-age=0\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.110 Safari/537.36\r\n\
Accept-Encoding: gzip,deflate,sdch\r\n\
Accept-Language: zh-CN,zh;q=0.8\r\n\
Cookie: BAIDUID=985DCDB8DFDC03CA1D0F37415A031049:FG=1; SSUDBTSP=1370755840;\r\n\r\n"));
	client.nbytes_read = strlen(client.buf);
	int r = php_http_read_request(&client, &errstr);
	printf("php_cli_server_client, ret = %d\n", r);
	swBreakPoint();
	return 0;
}

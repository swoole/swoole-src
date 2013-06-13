/*
 * http.c
 *
 *  Created on: 2013-6-3
 *      Author: htf
 */

#include "swoole.h"
#include "tests.h"

#include "deps/http_parser/http_parser.h"
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

swUnitTest(http_test1)
{
	int ret, i;
	//http_parser_settings settings;
	//settings.on_path = my_path_callback;
	//settings.on_header_field = on_header_field;

	char *url = "http://www.baidu.com:8080/index.php?hello=1#h";
	http_parser *parser = malloc(sizeof(http_parser));
	http_parser_init(parser, HTTP_REQUEST);
	//parser->data = "http://www.baidu.com/";
	struct http_parser_url *u = malloc(sizeof(struct http_parser_url));
	;
	ret = http_parser_parse_url(url, strlen(url), 0, u);

	printf("\tfield_set: 0x%x, port: %u\n", u->field_set, u->port);
	for (i = 0; i < UF_MAX; i++)
	{
		if ((u->field_set & (1 << i)) == 0)
		{
			printf("\tfield_data[%u]: unset\n", i);
			continue;
		}

		printf("\tfield_data[%u]: off: %u len: %u part: \"%.*s\n", i, u->field_data[i].off, u->field_data[i].len,
				u->field_data[i].len, url + u->field_data[i].off);
	}
	return 0;
}

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

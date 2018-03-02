/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#include "php_swoole.h"
#include "swoole_mysql.h"

#ifdef SW_USE_MYSQLND
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_charset.h"
#endif

static PHP_METHOD(swoole_mysql, __construct);
static PHP_METHOD(swoole_mysql, __destruct);
static PHP_METHOD(swoole_mysql, connect);
#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql, escape);
#endif
static PHP_METHOD(swoole_mysql, query);
static PHP_METHOD(swoole_mysql, begin);
static PHP_METHOD(swoole_mysql, commit);
static PHP_METHOD(swoole_mysql, rollback);
static PHP_METHOD(swoole_mysql, getState);
static PHP_METHOD(swoole_mysql, close);
static PHP_METHOD(swoole_mysql, on);

static zend_class_entry swoole_mysql_ce;
static zend_class_entry *swoole_mysql_class_entry_ptr;

static zend_class_entry swoole_mysql_exception_ce;
static zend_class_entry *swoole_mysql_exception_class_entry_ptr;

#define UTF8_MB4 "utf8mb4"
#define UTF8_MB3 "utf8"

typedef struct _mysql_charset
{
    unsigned int    nr;
    const char      *name;
    const char      *collation;
} mysql_charset;

static const mysql_charset swoole_mysql_charsets[] =
{
    { 1, "big5", "big5_chinese_ci" },
    { 3, "dec8", "dec8_swedish_ci" },
    { 4, "cp850", "cp850_general_ci" },
    { 6, "hp8", "hp8_english_ci" },
    { 7, "koi8r", "koi8r_general_ci" },
    { 8, "latin1", "latin1_swedish_ci" },
    { 5, "latin1", "latin1_german1_ci" },
    { 9, "latin2", "latin2_general_ci" },
    { 2, "latin2", "latin2_czech_cs" },
    { 10, "swe7", "swe7_swedish_ci" },
    { 11, "ascii", "ascii_general_ci" },
    { 12, "ujis", "ujis_japanese_ci" },
    { 13, "sjis", "sjis_japanese_ci" },
    { 16, "hebrew", "hebrew_general_ci" },
    { 17, "filename", "filename" },
    { 18, "tis620", "tis620_thai_ci" },
    { 19, "euckr", "euckr_korean_ci" },
    { 21, "latin2", "latin2_hungarian_ci" },
    { 27, "latin2", "latin2_croatian_ci" },
    { 22, "koi8u", "koi8u_general_ci" },
    { 24, "gb2312", "gb2312_chinese_ci" },
    { 25, "greek", "greek_general_ci" },
    { 26, "cp1250", "cp1250_general_ci" },
    { 28, "gbk", "gbk_chinese_ci" },
    { 30, "latin5", "latin5_turkish_ci" },
    { 31, "latin1", "latin1_german2_ci" },
    { 15, "latin1", "latin1_danish_ci" },
    { 32, "armscii8", "armscii8_general_ci" },
    { 33, UTF8_MB3, UTF8_MB3"_general_ci" },
    { 35, "ucs2", "ucs2_general_ci" },
    { 36, "cp866", "cp866_general_ci" },
    { 37, "keybcs2", "keybcs2_general_ci" },
    { 38, "macce", "macce_general_ci" },
    { 39, "macroman", "macroman_general_ci" },
    { 40, "cp852", "cp852_general_ci" },
    { 41, "latin7", "latin7_general_ci" },
    { 20, "latin7", "latin7_estonian_cs" },
    { 57, "cp1256", "cp1256_general_ci" },
    { 59, "cp1257", "cp1257_general_ci" },
    { 63, "binary", "binary" },
    { 97, "eucjpms", "eucjpms_japanese_ci" },
    { 29, "cp1257", "cp1257_lithuanian_ci" },
    { 31, "latin1", "latin1_german2_ci" },
    { 34, "cp1250", "cp1250_czech_cs" },
    { 42, "latin7", "latin7_general_cs" },
    { 43, "macce", "macce_bin" },
    { 44, "cp1250", "cp1250_croatian_ci" },
    { 45, UTF8_MB4, UTF8_MB4"_general_ci" },
    { 46, UTF8_MB4, UTF8_MB4"_bin" },
    { 47, "latin1", "latin1_bin" },
    { 48, "latin1", "latin1_general_ci" },
    { 49, "latin1", "latin1_general_cs" },
    { 51, "cp1251", "cp1251_general_ci" },
    { 14, "cp1251", "cp1251_bulgarian_ci" },
    { 23, "cp1251", "cp1251_ukrainian_ci" },
    { 50, "cp1251", "cp1251_bin" },
    { 52, "cp1251", "cp1251_general_cs" },
    { 53, "macroman", "macroman_bin" },
    { 54, "utf16", "utf16_general_ci" },
    { 55, "utf16", "utf16_bin" },
    { 56, "utf16le", "utf16le_general_ci" },
    { 58, "cp1257", "cp1257_bin" },
    { 60, "utf32", "utf32_general_ci" },
    { 61, "utf32", "utf32_bin" },
    { 62, "utf16le", "utf16le_bin" },
    { 64, "armscii8", "armscii8_bin" },
    { 65, "ascii", "ascii_bin" },
    { 66, "cp1250", "cp1250_bin" },
    { 67, "cp1256", "cp1256_bin" },
    { 68, "cp866", "cp866_bin" },
    { 69, "dec8", "dec8_bin" },
    { 70, "greek", "greek_bin" },
    { 71, "hebrew", "hebrew_bin" },
    { 72, "hp8", "hp8_bin" },
    { 73, "keybcs2", "keybcs2_bin" },
    { 74, "koi8r", "koi8r_bin" },
    { 75, "koi8u", "koi8u_bin" },
    { 77, "latin2", "latin2_bin" },
    { 78, "latin5", "latin5_bin" },
    { 79, "latin7", "latin7_bin" },
    { 80, "cp850", "cp850_bin" },
    { 81, "cp852", "cp852_bin" },
    { 82, "swe7", "swe7_bin" },
    { 83, UTF8_MB3, UTF8_MB3"_bin" },
    { 84, "big5", "big5_bin" },
    { 85, "euckr", "euckr_bin" },
    { 86, "gb2312", "gb2312_bin" },
    { 87, "gbk", "gbk_bin" },
    { 88, "sjis", "sjis_bin" },
    { 89, "tis620", "tis620_bin" },
    { 90, "ucs2", "ucs2_bin" },
    { 91, "ujis", "ujis_bin" },
    { 92, "geostd8", "geostd8_general_ci" },
    { 93, "geostd8", "geostd8_bin" },
    { 94, "latin1", "latin1_spanish_ci" },
    { 95, "cp932", "cp932_japanese_ci" },
    { 96, "cp932", "cp932_bin" },
    { 97, "eucjpms", "eucjpms_japanese_ci" },
    { 98, "eucjpms", "eucjpms_bin" },
    { 99, "cp1250", "cp1250_polish_ci" },
    { 128, "ucs2", "ucs2_unicode_ci" },
    { 129, "ucs2", "ucs2_icelandic_ci" },
    { 130, "ucs2", "ucs2_latvian_ci" },
    { 131, "ucs2", "ucs2_romanian_ci" },
    { 132, "ucs2", "ucs2_slovenian_ci" },
    { 133, "ucs2", "ucs2_polish_ci" },
    { 134, "ucs2", "ucs2_estonian_ci" },
    { 135, "ucs2", "ucs2_spanish_ci" },
    { 136, "ucs2", "ucs2_swedish_ci" },
    { 137, "ucs2", "ucs2_turkish_ci" },
    { 138, "ucs2", "ucs2_czech_ci" },
    { 139, "ucs2", "ucs2_danish_ci" },
    { 140, "ucs2", "ucs2_lithuanian_ci" },
    { 141, "ucs2", "ucs2_slovak_ci" },
    { 142, "ucs2", "ucs2_spanish2_ci" },
    { 143, "ucs2", "ucs2_roman_ci" },
    { 144, "ucs2", "ucs2_persian_ci" },
    { 145, "ucs2", "ucs2_esperanto_ci" },
    { 146, "ucs2", "ucs2_hungarian_ci" },
    { 147, "ucs2", "ucs2_sinhala_ci" },
    { 148, "ucs2", "ucs2_german2_ci" },
    { 149, "ucs2", "ucs2_croatian_ci" },
    { 150, "ucs2", "ucs2_unicode_520_ci" },
    { 151, "ucs2", "ucs2_vietnamese_ci" },
    { 160, "utf32", "utf32_unicode_ci" },
    { 161, "utf32", "utf32_icelandic_ci" },
    { 162, "utf32", "utf32_latvian_ci" },
    { 163, "utf32", "utf32_romanian_ci" },
    { 164, "utf32", "utf32_slovenian_ci" },
    { 165, "utf32", "utf32_polish_ci" },
    { 166, "utf32", "utf32_estonian_ci" },
    { 167, "utf32", "utf32_spanish_ci" },
    { 168, "utf32", "utf32_swedish_ci" },
    { 169, "utf32", "utf32_turkish_ci" },
    { 170, "utf32", "utf32_czech_ci" },
    { 171, "utf32", "utf32_danish_ci" },
    { 172, "utf32", "utf32_lithuanian_ci" },
    { 173, "utf32", "utf32_slovak_ci" },
    { 174, "utf32", "utf32_spanish2_ci" },
    { 175, "utf32", "utf32_roman_ci" },
    { 176, "utf32", "utf32_persian_ci" },
    { 177, "utf32", "utf32_esperanto_ci" },
    { 178, "utf32", "utf32_hungarian_ci" },
    { 179, "utf32", "utf32_sinhala_ci" },
    { 180, "utf32", "utf32_german2_ci" },
    { 181, "utf32", "utf32_croatian_ci" },
    { 182, "utf32", "utf32_unicode_520_ci" },
    { 183, "utf32", "utf32_vietnamese_ci" },
    { 192, UTF8_MB3, UTF8_MB3"_unicode_ci" },
    { 193, UTF8_MB3, UTF8_MB3"_icelandic_ci" },
    { 194, UTF8_MB3, UTF8_MB3"_latvian_ci" },
    { 195, UTF8_MB3, UTF8_MB3"_romanian_ci" },
    { 196, UTF8_MB3, UTF8_MB3"_slovenian_ci" },
    { 197, UTF8_MB3, UTF8_MB3"_polish_ci" },
    { 198, UTF8_MB3, UTF8_MB3"_estonian_ci" },
    { 199, UTF8_MB3, UTF8_MB3"_spanish_ci" },
    { 200, UTF8_MB3, UTF8_MB3"_swedish_ci" },
    { 201, UTF8_MB3, UTF8_MB3"_turkish_ci" },
    { 202, UTF8_MB3, UTF8_MB3"_czech_ci" },
    { 203, UTF8_MB3, UTF8_MB3"_danish_ci" },
    { 204, UTF8_MB3, UTF8_MB3"_lithuanian_ci" },
    { 205, UTF8_MB3, UTF8_MB3"_slovak_ci" },
    { 206, UTF8_MB3, UTF8_MB3"_spanish2_ci" },
    { 207, UTF8_MB3, UTF8_MB3"_roman_ci" },
    { 208, UTF8_MB3, UTF8_MB3"_persian_ci" },
    { 209, UTF8_MB3, UTF8_MB3"_esperanto_ci" },
    { 210, UTF8_MB3, UTF8_MB3"_hungarian_ci" },
    { 211, UTF8_MB3, UTF8_MB3"_sinhala_ci" },
    { 212, UTF8_MB3, UTF8_MB3"_german2_ci" },
    { 213, UTF8_MB3, UTF8_MB3"_croatian_ci" },
    { 214, UTF8_MB3, UTF8_MB3"_unicode_520_ci" },
    { 215, UTF8_MB3, UTF8_MB3"_vietnamese_ci" },

    { 224, UTF8_MB4, UTF8_MB4"_unicode_ci" },
    { 225, UTF8_MB4, UTF8_MB4"_icelandic_ci" },
    { 226, UTF8_MB4, UTF8_MB4"_latvian_ci" },
    { 227, UTF8_MB4, UTF8_MB4"_romanian_ci" },
    { 228, UTF8_MB4, UTF8_MB4"_slovenian_ci" },
    { 229, UTF8_MB4, UTF8_MB4"_polish_ci" },
    { 230, UTF8_MB4, UTF8_MB4"_estonian_ci" },
    { 231, UTF8_MB4, UTF8_MB4"_spanish_ci" },
    { 232, UTF8_MB4, UTF8_MB4"_swedish_ci" },
    { 233, UTF8_MB4, UTF8_MB4"_turkish_ci" },
    { 234, UTF8_MB4, UTF8_MB4"_czech_ci" },
    { 235, UTF8_MB4, UTF8_MB4"_danish_ci" },
    { 236, UTF8_MB4, UTF8_MB4"_lithuanian_ci" },
    { 237, UTF8_MB4, UTF8_MB4"_slovak_ci" },
    { 238, UTF8_MB4, UTF8_MB4"_spanish2_ci" },
    { 239, UTF8_MB4, UTF8_MB4"_roman_ci" },
    { 240, UTF8_MB4, UTF8_MB4"_persian_ci" },
    { 241, UTF8_MB4, UTF8_MB4"_esperanto_ci" },
    { 242, UTF8_MB4, UTF8_MB4"_hungarian_ci" },
    { 243, UTF8_MB4, UTF8_MB4"_sinhala_ci" },
    { 244, UTF8_MB4, UTF8_MB4"_german2_ci" },
    { 245, UTF8_MB4, UTF8_MB4"_croatian_ci" },
    { 246, UTF8_MB4, UTF8_MB4"_unicode_520_ci" },
    { 247, UTF8_MB4, UTF8_MB4"_vietnamese_ci" },
    { 248, "gb18030", "gb18030_chinese_ci" },
    { 249, "gb18030", "gb18030_bin" },
    { 254, UTF8_MB3, UTF8_MB3"_general_cs" },
    { 0, NULL, NULL},
};


ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_connect, 0, 0, 2)
    ZEND_ARG_ARRAY_INFO(0, server_config, 0)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_begin, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_commit, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_rollback, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

#ifdef SW_USE_MYSQLND
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_escape, 0, 0, 1)
    ZEND_ARG_INFO(0, string)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_query, 0, 0, 2)
    ZEND_ARG_INFO(0, sql)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_mysql_methods[] =
{
    PHP_ME(swoole_mysql, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_mysql, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_mysql, connect, arginfo_swoole_mysql_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, begin, arginfo_swoole_mysql_begin, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, commit, arginfo_swoole_mysql_commit, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, rollback, arginfo_swoole_mysql_rollback, ZEND_ACC_PUBLIC)
#ifdef SW_USE_MYSQLND
    PHP_ME(swoole_mysql, escape, arginfo_swoole_mysql_escape, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_mysql, query, arginfo_swoole_mysql_query, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, getState, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, on, arginfo_swoole_mysql_on, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static void mysql_client_free(mysql_client *client, zval* zobject);
static void mysql_columns_free(mysql_client *client);

static void mysql_client_free(mysql_client *client, zval* zobject)
{
    if (client->cli->timer)
    {
        swTimer_del(&SwooleG.timer, client->cli->timer);
        client->cli->timer = NULL;
    }
    //close the connection
    client->cli->close(client->cli);
    //release client object memory
    swClient_free(client->cli);
    efree(client->cli);
    client->cli = NULL;
    client->connected = 0;
}

static void mysql_columns_free(mysql_client *client)
{
    int i;
    for (i = 0; i < client->response.num_column; i++)
    {
        if (client->response.columns[i].buffer)
        {
            efree(client->response.columns[i].buffer);
            client->response.columns[i].buffer = NULL;
        }
    }
    efree(client->response.columns);
}

#ifdef SW_MYSQL_DEBUG
static void mysql_client_info(mysql_client *client);
static void mysql_column_info(mysql_field *field);
#endif

static void swoole_mysql_onTimeout(swTimer *timer, swTimer_node *tnode);
static int swoole_mysql_onRead(swReactor *reactor, swEvent *event);
static int swoole_mysql_onWrite(swReactor *reactor, swEvent *event);
static int swoole_mysql_onError(swReactor *reactor, swEvent *event);
static void swoole_mysql_onConnect(mysql_client *client TSRMLS_DC);

swString *mysql_request_buffer = NULL;

void swoole_mysql_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_mysql_ce, "swoole_mysql", "Swoole\\MySQL", swoole_mysql_methods);
    swoole_mysql_class_entry_ptr = zend_register_internal_class(&swoole_mysql_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_mysql, "Swoole\\MySQL");

    SWOOLE_INIT_CLASS_ENTRY(swoole_mysql_exception_ce, "swoole_mysql_exception", "Swoole\\MySQL\\Exception", NULL);
    swoole_mysql_exception_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_mysql_exception_ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_mysql_exception, "Swoole\\MySQL\\Exception");

    zend_declare_property_null(swoole_mysql_class_entry_ptr, ZEND_STRL("serverInfo"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_mysql_class_entry_ptr, ZEND_STRL("sock"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_mysql_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("errno"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("connect_errno"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_mysql_class_entry_ptr, ZEND_STRL("error"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_mysql_class_entry_ptr, ZEND_STRL("connect_error"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_mysql_class_entry_ptr, ZEND_STRL("insert_id"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_mysql_class_entry_ptr, ZEND_STRL("affected_rows"), ZEND_ACC_PUBLIC TSRMLS_CC);
    /**
     * event callback
     */
    zend_declare_property_null(swoole_mysql_class_entry_ptr, ZEND_STRL("onConnect"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_mysql_class_entry_ptr, ZEND_STRL("onClose"), ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_class_constant_long(swoole_mysql_class_entry_ptr, SW_STRL("STATE_QUERY")-1, SW_MYSQL_STATE_QUERY TSRMLS_CC);
    zend_declare_class_constant_long(swoole_mysql_class_entry_ptr, SW_STRL("STATE_READ_START")-1, SW_MYSQL_STATE_READ_START TSRMLS_CC);
    zend_declare_class_constant_long(swoole_mysql_class_entry_ptr, SW_STRL("STATE_READ_FIELD ")-1, SW_MYSQL_STATE_READ_FIELD TSRMLS_CC);
    zend_declare_class_constant_long(swoole_mysql_class_entry_ptr, SW_STRL("STATE_READ_ROW")-1, SW_MYSQL_STATE_READ_ROW TSRMLS_CC);
    zend_declare_class_constant_long(swoole_mysql_class_entry_ptr, SW_STRL("STATE_READ_END")-1, SW_MYSQL_STATE_READ_END TSRMLS_CC);
    zend_declare_class_constant_long(swoole_mysql_class_entry_ptr, SW_STRL("STATE_CLOSED")-1, SW_MYSQL_STATE_CLOSED TSRMLS_CC);
}

int mysql_request(swString *sql, swString *buffer)
{
    bzero(buffer->str, 5);
    //length
    mysql_pack_length(sql->length + 1, buffer->str);
    //command
    buffer->str[4] = SW_MYSQL_COM_QUERY;
    buffer->length = 5;
    return swString_append(buffer, sql);
}

int mysql_prepare(swString *sql, swString *buffer)
{
    bzero(buffer->str, 5);
    //length
    mysql_pack_length(sql->length + 1, buffer->str);
    //command
    buffer->str[4] = SW_MYSQL_COM_STMT_PREPARE;
    buffer->length = 5;
    return swString_append(buffer, sql);
}

int mysql_get_charset(char *name)
{
    const mysql_charset *c = swoole_mysql_charsets;
    while (c[0].nr != 0)
    {
        if (!strcasecmp(c->name, name))
        {
            return c->nr;
        }
        ++c;
    }
    return -1;
}

int mysql_get_result(mysql_connector *connector, char *buf, int len)
{
    char *tmp = buf;
    int packet_length = mysql_uint3korr(tmp);
    if (len < packet_length + 4)
    {
        return 0;
    }
    //int packet_number = tmp[3];
    tmp += 4;

    uint8_t opcode = *tmp;
    tmp += 1;

    //ERROR Packet
    if (opcode == 0xff)
    {
        connector->error_code = *(uint16_t *) tmp;
        connector->error_msg = tmp + 2;
        connector->error_length = packet_length - 3;
        return -1;
    }
    else
    {
        return 1;
    }
}

/**
1              [0a] protocol version
string[NUL]    server version
4              connection id
string[8]      auth-plugin-data-part-1
1              [00] filler
2              capability flags (lower 2 bytes)
  if more data in the packet:
1              character set
2              status flags
2              capability flags (upper 2 bytes)
  if capabilities & CLIENT_PLUGIN_AUTH {
1              length of auth-plugin-data
  } else {
1              [00]
  }
string[10]     reserved (all [00])
  if capabilities & CLIENT_SECURE_CONNECTION {
string[$len]   auth-plugin-data-part-2 ($len=MAX(13, length of auth-plugin-data - 8))
  if capabilities & CLIENT_PLUGIN_AUTH {
string[NUL]    auth-plugin name
  }
 */
int mysql_handshake(mysql_connector *connector, char *buf, int len)
{
    char *tmp = buf;

    /**
     * handshake request
     */
    mysql_handshake_request request;
    bzero(&request, sizeof(request));

    request.packet_length = mysql_uint3korr(tmp);
    //continue to wait for data
    if (len < request.packet_length + 4)
    {
        return 0;
    }

    request.packet_number = tmp[3];
    tmp += 4;

    request.protocol_version = *tmp;
    tmp += 1;

    //ERROR Packet
    if (request.protocol_version == 0xff)
    {
        connector->error_code = *(uint16_t *) tmp;
        connector->error_msg = tmp + 2;
        connector->error_length = request.packet_length - 3;
        return -1;
    }

    //1              [0a] protocol version
    request.server_version = tmp;
    tmp += (strlen(request.server_version) + 1);
    //4              connection id
    request.connection_id = *((int *) tmp);
    tmp += 4;
    //string[8]      auth-plugin-data-part-1
    memcpy(request.auth_plugin_data, tmp, 8);
    tmp += 8;
    //1              [00] filler
    request.filler = *tmp;
    tmp += 1;
    //2              capability flags (lower 2 bytes)
    memcpy(((char *) (&request.capability_flags)), tmp, 2);
    tmp += 2;

    if (tmp - tmp < len)
    {
        //1              character set
        request.character_set = *tmp;
        tmp += 1;
        //2              status flags
        memcpy(&request.status_flags, tmp, 2);
        tmp += 2;
        //2              capability flags (upper 2 bytes)
        memcpy(((char *) (&request.capability_flags) + 2), tmp, 2);
        tmp += 2;

        request.l_auth_plugin_data = *tmp;
        tmp += 1;

        memcpy(&request.reserved, tmp, sizeof(request.reserved));
        tmp += sizeof(request.reserved);

        if (request.capability_flags & SW_MYSQL_CLIENT_SECURE_CONNECTION)
        {
            int len = MAX(13, request.l_auth_plugin_data - 8);
            memcpy(request.auth_plugin_data + 8, tmp, len);
            tmp += len;
        }

        if (request.capability_flags & SW_MYSQL_CLIENT_PLUGIN_AUTH)
        {
            request.auth_plugin_name = tmp;
            request.l_auth_plugin_name = MIN(strlen(tmp), len - (tmp - buf));
        }
    }

    int value;
    tmp = connector->buf + 4;

    //capability flags, CLIENT_PROTOCOL_41 always set
    value = SW_MYSQL_CLIENT_PROTOCOL_41 | SW_MYSQL_CLIENT_SECURE_CONNECTION | SW_MYSQL_CLIENT_CONNECT_WITH_DB | SW_MYSQL_CLIENT_PLUGIN_AUTH;
    memcpy(tmp, &value, sizeof(value));
    tmp += 4;

    //max-packet size
    value = 300;
    memcpy(tmp, &value, sizeof(value));
    tmp += 4;

    //use the server character_set when the character_set is not set.
    if (connector->character_set == 0)
    {
        connector->character_set = request.character_set;
    }

    //character set
    *tmp = connector->character_set;
    tmp += 1;

    //string[23]     reserved (all [0])
    tmp += 23;

    //string[NUL]    username
    memcpy(tmp, connector->user, connector->user_len);
    tmp[connector->user_len] = '\0';
    tmp += (connector->user_len + 1);

    if (connector->password_len > 0)
    {
        //auth-response
        char hash_0[20];
        bzero(hash_0, sizeof (hash_0));
        php_swoole_sha1(connector->password, connector->password_len, (uchar *) hash_0);

        char hash_1[20];
        bzero(hash_1, sizeof (hash_1));
        php_swoole_sha1(hash_0, sizeof (hash_0), (uchar *) hash_1);

        char str[40];
        memcpy(str, request.auth_plugin_data, 20);
        memcpy(str + 20, hash_1, 20);

        char hash_2[20];
        php_swoole_sha1(str, sizeof (str), (uchar *) hash_2);

        char hash_3[20];

        int *a = (int *) hash_2;
        int *b = (int *) hash_0;
        int *c = (int *) hash_3;

        int i;
        for (i = 0; i < 5; i++)
        {
            c[i] = a[i] ^ b[i];
        }

        *tmp = 20;
        memcpy(tmp + 1, hash_3, 20);
        tmp += 21;
    }
    else
    {
         *tmp = 0;
         tmp++;
    }

    //string[NUL]    database
    memcpy(tmp, connector->database, connector->database_len);
    tmp[connector->database_len] = '\0';
    tmp += (connector->database_len + 1);

    //string[NUL]    auth plugin name
    memcpy(tmp, request.auth_plugin_name, request.l_auth_plugin_name);
    tmp[request.l_auth_plugin_name] = '\0';
    tmp += (request.l_auth_plugin_name + 1);

    connector->packet_length = tmp - connector->buf - 4;
    mysql_pack_length(connector->packet_length, connector->buf);
    connector->buf[3] = 1;

    return 1;
}

static int mysql_parse_prepare_result(mysql_client *client, char *buf, size_t n_buf)
{
    if (n_buf < 11)
    {
        return SW_ERR;
    }

    mysql_statement *stmt = emalloc(sizeof(mysql_statement));
    stmt->id = mysql_uint4korr(buf);
    buf += 4;
    stmt->field_count = mysql_uint2korr(buf);
    buf += 2;
    stmt->unreaded_param_count = stmt->param_count = mysql_uint2korr(buf);
    buf += 2;
    //skip 1 byte
    buf += 1;
    stmt->warning_count = mysql_uint2korr(buf);
    client->statement = stmt;
    stmt->client = client;

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "id=%d, field_count=%d, param_count=%d, warning_count=%d.", stmt->id, stmt->field_count, stmt->param_count,
            stmt->warning_count);

    return 11;
}

static int mysql_decode_row(mysql_client *client, char *buf, int packet_len)
{
    int read_n = 0, i;
    int tmp_len;
    ulong_t len;
    char nul;

    mysql_row row;
    char value_buffer[32];
    bzero(&row, sizeof(row));
    char *error;
    //unused
    //char mem;

    zval *result_array = client->response.result_array;
    zval *row_array = NULL;
    SW_ALLOC_INIT_ZVAL(row_array);
    array_init(row_array);

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "mysql_decode_row begin, num_column=%d, packet_len=%d.", client->response.num_column, packet_len);

    for (i = 0; i < client->response.num_column; i++)
    {
        tmp_len = mysql_length_coded_binary(&buf[read_n], &len, &nul, packet_len - read_n);
        if (tmp_len == -1)
        {
            return -SW_MYSQL_ERR_BAD_LCB;
        }

        read_n += tmp_len;
        if (read_n + len > packet_len)
        {
            return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
        }

        swTraceLog(SW_TRACE_MYSQL_CLIENT, "n=%d, fname=%s, name_length=%d", i, client->response.columns[i].name,
                client->response.columns[i].name_length);

        if (nul == 1)
        {
            add_assoc_null(row_array, client->response.columns[i].name);
            continue;
        }

        int type = client->response.columns[i].type;

        swTraceLog(SW_TRACE_MYSQL_CLIENT, "value: name=%s, type=%d, value=%s, len=%ld",
                client->response.columns[i].name, type, swoole_strndup(buf + read_n, len), len);

        switch (type)
        {
        case SW_MYSQL_TYPE_NULL:
            add_assoc_null(row_array, client->response.columns[i].name);
            break;
        /* String */
        case SW_MYSQL_TYPE_TINY_BLOB:
        case SW_MYSQL_TYPE_MEDIUM_BLOB:
        case SW_MYSQL_TYPE_LONG_BLOB:
        case SW_MYSQL_TYPE_BLOB:
        case SW_MYSQL_TYPE_DECIMAL:
        case SW_MYSQL_TYPE_NEWDECIMAL:
        case SW_MYSQL_TYPE_BIT:
        case SW_MYSQL_TYPE_STRING:
        case SW_MYSQL_TYPE_VAR_STRING:
        case SW_MYSQL_TYPE_VARCHAR:
        case SW_MYSQL_TYPE_NEWDATE:
        /* Date Time */
        case SW_MYSQL_TYPE_TIME:
        case SW_MYSQL_TYPE_YEAR:
        case SW_MYSQL_TYPE_TIMESTAMP:
        case SW_MYSQL_TYPE_DATETIME:
        case SW_MYSQL_TYPE_DATE:
        case SW_MYSQL_TYPE_JSON:
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
            break;
        /* Integer */
        case SW_MYSQL_TYPE_TINY:
        case SW_MYSQL_TYPE_SHORT:
        case SW_MYSQL_TYPE_INT24:
        case SW_MYSQL_TYPE_LONG:
            if(client->connector.strict_type)
            {
                memcpy(value_buffer, buf + read_n, len);
                value_buffer[len] = 0;
                row.sint = strtol(value_buffer, &error, 10);
                if (*error != '\0')
                {
                    return -SW_MYSQL_ERR_CONVLONG;
                }
                add_assoc_long(row_array, client->response.columns[i].name, row.sint);
            }
            else
            {
                sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);

            }
            break;
        case SW_MYSQL_TYPE_LONGLONG:
            if(client->connector.strict_type) {
                memcpy(value_buffer, buf + read_n, len);
                value_buffer[len] = 0;
                row.sbigint = strtoll(value_buffer, &error, 10);
                if (*error != '\0') {
                    return -SW_MYSQL_ERR_CONVLONG;
                }
                add_assoc_long(row_array, client->response.columns[i].name, row.sbigint);
            }
            else
            {
                sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);

            }
            break;
        case SW_MYSQL_TYPE_FLOAT:
            if(client->connector.strict_type) {
                memcpy(value_buffer, buf + read_n, len);
                value_buffer[len] = 0;
                row.mfloat = strtof(value_buffer, &error);
                if (*error != '\0') {
                    return -SW_MYSQL_ERR_CONVFLOAT;
                }
                add_assoc_double(row_array, client->response.columns[i].name, row.mfloat);
            }
            else
            {
                sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
            }
            break;

        case SW_MYSQL_TYPE_DOUBLE:
            if(client->connector.strict_type) {
                memcpy(value_buffer, buf + read_n, len);
                value_buffer[len] = 0;
                row.mdouble = strtod(value_buffer, &error);
                if (*error != '\0') {
                    return -SW_MYSQL_ERR_CONVDOUBLE;
                }
                add_assoc_double(row_array, client->response.columns[i].name, row.mdouble);
            }
            else
            {
                sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);

            }
            break;

        default:
            swWarn("unknown field type[%d].", type);
            return -1;
        }
        read_n += len;
    }

    add_next_index_zval(result_array, row_array);

#if PHP_MAJOR_VERSION > 5
    if (row_array)
    {
        efree(row_array);
    }
#endif

    return read_n;
}

#define DATETIME_MAX_SIZE  20

static int mysql_decode_datetime(char *buf, char *result)
{
    uint16_t y = 0;
    uint8_t M = 0, d = 0, h = 0, m = 0, s = 0, n;

    n = *(uint8_t *) (buf);
    if (n != 0)
    {
        y = *(uint16_t *) (buf + 1);
        M = *(uint8_t *) (buf + 3);
        d = *(uint8_t *) (buf + 4);
        h = *(uint8_t *) (buf + 5);
        m = *(uint8_t *) (buf + 6);
        s = *(uint8_t *) (buf + 7);
    }
    snprintf(result, DATETIME_MAX_SIZE, "%04d-%02d-%02d %02d:%02d:%02d", y, M, d, h, m, s);

    swTrace("n=%d\n", n);

    return n;
}

static int mysql_decode_time(char *buf, char *result)
{
    uint8_t h = 0, m = 0, s = 0;

    uint8_t n = *(uint8_t *) (buf);
    if (n != 0)
    {
        h = *(uint8_t *) (buf + 6);
        m = *(uint8_t *) (buf + 7);
        s = *(uint8_t *) (buf + 8);
    }

    snprintf(result, DATETIME_MAX_SIZE, "%02d:%02d:%02d", h, m, s);

    return n;
}

static int mysql_decode_date(char *buf, char *result)
{
    uint8_t M = 0, d = 0, n;
    uint16_t y = 0;

    n = *(uint8_t *) (buf);
    if (n != 0)
    {
        y = *(uint16_t *) (buf + 1);
        M = *(uint8_t *) (buf + 3);
        d = *(uint8_t *) (buf + 4);
    }
    snprintf(result, DATETIME_MAX_SIZE, "%04d-%02d-%02d", y, M, d);
    return n;
}

static void mysql_decode_year(char *buf, char *result)
{
    uint16_t y;
    y = *(uint16_t *) (buf + 1);
    snprintf(result, DATETIME_MAX_SIZE, "%04d", y);
}

static int mysql_decode_row_prepare(mysql_client *client, char *buf, int packet_len)
{
    int read_n = 0, i;
    int tmp_len;
    ulong_t len = 0;
    char nul;

    unsigned int null_count = ((client->response.num_column + 9) / 8) + 1;
    buf += null_count;
    packet_len -= null_count;

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "null_count=%d", null_count);

    char datetime_buffer[DATETIME_MAX_SIZE];
    mysql_row row;

    zval *result_array = client->response.result_array;
    zval *row_array = NULL;
    SW_ALLOC_INIT_ZVAL(row_array);
    array_init(row_array);

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "mysql_decode_row begin, num_column=%d, packet_len=%d.", client->response.num_column, packet_len);

    for (i = 0; i < client->response.num_column; i++)
    {
        /* to check Null-Bitmap @see https://dev.mysql.com/doc/internals/en/null-bitmap.html */
        if( ( (buf - null_count + 1)[((i+2)/8)] & (0x01 << ((i+2)%8)) ) != 0 ){
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "value: %s is null ,flag2", client->response.columns[i].name);
            add_assoc_null(row_array, client->response.columns[i].name);
            continue;
        }

        int type = client->response.columns[i].type;
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "value: name=%s, type=%d", client->response.columns[i].name, type);
        switch (type)
        {
        /* Date Time */
        case SW_MYSQL_TYPE_TIME:
            len = mysql_decode_time(buf + read_n, datetime_buffer);
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, datetime_buffer, 8, 1);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%s", client->response.columns[i].name, datetime_buffer);
            break;

        case SW_MYSQL_TYPE_YEAR:
            mysql_decode_year(buf + read_n, datetime_buffer);
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, datetime_buffer, 4, 1);
            len = 3;
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%s", client->response.columns[i].name, datetime_buffer);
            break;

        case SW_MYSQL_TYPE_DATE:
            len = mysql_decode_date(buf + read_n, datetime_buffer) + 1;
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, datetime_buffer, 10, 1);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%s", client->response.columns[i].name, datetime_buffer);
            break;

        case SW_MYSQL_TYPE_TIMESTAMP:
        case SW_MYSQL_TYPE_DATETIME:
            len = mysql_decode_datetime(buf + read_n, datetime_buffer) + 1;
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, datetime_buffer, 19, 1);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%s", client->response.columns[i].name, datetime_buffer);
            break;

        case SW_MYSQL_TYPE_NULL:
            add_assoc_null(row_array, client->response.columns[i].name);
            break;

        /* String */
        case SW_MYSQL_TYPE_TINY_BLOB:
        case SW_MYSQL_TYPE_MEDIUM_BLOB:
        case SW_MYSQL_TYPE_LONG_BLOB:
        case SW_MYSQL_TYPE_BLOB:
        case SW_MYSQL_TYPE_DECIMAL:
        case SW_MYSQL_TYPE_NEWDECIMAL:
        case SW_MYSQL_TYPE_BIT:
        case SW_MYSQL_TYPE_JSON:
        case SW_MYSQL_TYPE_STRING:
        case SW_MYSQL_TYPE_VAR_STRING:
        case SW_MYSQL_TYPE_VARCHAR:
        case SW_MYSQL_TYPE_NEWDATE:
            tmp_len = mysql_length_coded_binary(&buf[read_n], &len, &nul, packet_len - read_n);
            if (tmp_len == -1)
            {
                return -SW_MYSQL_ERR_BAD_LCB;
            }
            read_n += tmp_len;
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%s", client->response.columns[i].name, swoole_strndup(buf + read_n, len));
            break;

        /* Integer */
        case SW_MYSQL_TYPE_TINY:
            row.stiny = *(int8_t *) (buf + read_n);
            add_assoc_long(row_array, client->response.columns[i].name, row.stiny);
            len = sizeof(row.stiny);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%d", client->response.columns[i].name, row.stiny);
            break;

        case SW_MYSQL_TYPE_SHORT:
            row.ssmall = *(int16_t *) (buf + read_n);
            add_assoc_long(row_array, client->response.columns[i].name, row.ssmall);
            len = sizeof(row.ssmall);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%d", client->response.columns[i].name, row.ssmall);
            break;

        case SW_MYSQL_TYPE_INT24:
        case SW_MYSQL_TYPE_LONG:
            row.sint = *(int32_t *) (buf + read_n);
            add_assoc_long(row_array, client->response.columns[i].name, row.sint);
            len = sizeof(row.sint);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%d", client->response.columns[i].name, row.sint);
            break;

        case SW_MYSQL_TYPE_LONGLONG:
            row.sbigint = *(int64_t *) (buf + read_n);
            add_assoc_long(row_array, client->response.columns[i].name, row.sbigint);
            len = sizeof(row.sbigint);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%ld", client->response.columns[i].name, row.sbigint);
            break;

        case SW_MYSQL_TYPE_FLOAT:
            row.mfloat = *(float *) (buf + read_n);
            add_assoc_double(row_array, client->response.columns[i].name, row.mfloat);
            len = sizeof(row.mfloat);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%f", client->response.columns[i].name, row.mfloat);
            break;

        case SW_MYSQL_TYPE_DOUBLE:
            row.mdouble = *(double *) (buf + read_n);
            add_assoc_double(row_array, client->response.columns[i].name, row.mdouble);
            len = sizeof(row.mdouble);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%f", client->response.columns[i].name, row.mdouble);
            break;

        default:
            swWarn("unknown field type[%d].", type);
            return -1;
        }
        read_n += len;
    }

    add_next_index_zval(result_array, row_array);

#if PHP_MAJOR_VERSION > 5
    if (row_array)
    {
        efree(row_array);
    }
#endif

    return read_n + null_count;
}

static sw_inline int mysql_read_eof(mysql_client *client, char *buffer, int n_buf)
{
    //EOF, length (3byte) + id(1byte) + 0xFE + warning(2byte) + status(2byte)
    if (n_buf < 9)
    {
        client->response.wait_recv = 1;
        return SW_ERR;
    }

    client->response.packet_length = mysql_uint3korr(buffer);
    client->response.packet_number = buffer[3];

    //not EOF packet
    uint8_t eof = buffer[4];
    if (eof != 0xfe)
    {
        return SW_ERR;
    }

    client->response.warnings = mysql_uint2korr(buffer + 5);
    client->response.status_code = mysql_uint2korr(buffer + 7);

    return SW_OK;
}

static sw_inline int mysql_read_params(mysql_client *client)
{
    while (1)
    {
        char *buffer = client->buffer->str + client->buffer->offset;
        uint32_t n_buf = client->buffer->length - client->buffer->offset;

        swTraceLog(SW_TRACE_MYSQL_CLIENT, "n_buf=%d, length=%d.", n_buf, client->response.packet_length);

        if (n_buf < 4)
        {
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "read eof [1]");
            return SW_ERR;
        }

        if (client->statement->unreaded_param_count > 0)
        {
            //no enough data
            if (n_buf - 4 < client->response.packet_length)
            {
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "read eof 234234.");
                return SW_ERR;
            }
            // Read and ignore parameter field. Sentence from MySQL source:
            // skip parameters data: we don't support it yet
            client->response.packet_length = mysql_uint3korr(buffer);
            client->response.packet_number = buffer[3];
            client->buffer->offset += (client->response.packet_length + 4);
            client->statement->unreaded_param_count--;

            swTraceLog(SW_TRACE_MYSQL_CLIENT, "read param, count=%d.", client->statement->unreaded_param_count);

            continue;
        }
        else
        {
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "read eof [2]");

            if (mysql_read_eof(client, buffer, n_buf) == 0)
            {
                client->buffer->offset += 9;
                return SW_OK;
            }
            else
            {
                return SW_ERR;
            }
        }
    }
}

static sw_inline int mysql_read_rows(mysql_client *client)
{
    char *buffer = client->buffer->str + client->buffer->offset;
    uint32_t n_buf = client->buffer->length - client->buffer->offset;
    int ret;

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "n_buf=%d", n_buf);

    //RecordSet parse
    while (n_buf > 0)
    {
        if (n_buf < 4)
        {
            client->response.wait_recv = 1;
            return SW_ERR;
        }
        //RecordSet end
        else if (n_buf == 9 && mysql_read_eof(client, buffer, n_buf) == 0)
        {
            if (client->response.columns)
            {
                mysql_columns_free(client);
            }
            return SW_OK;
        }

        client->response.packet_length = mysql_uint3korr(buffer);
        client->response.packet_number = buffer[3];
        buffer += 4;
        n_buf -= 4;

        swTraceLog(SW_TRACE_MYSQL_CLIENT, "record size=%d", client->response.packet_length);

        //no enough data
        if (n_buf < client->response.packet_length)
        {
            client->response.wait_recv = 1;
            return SW_ERR;
        }

        if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
        {
            ret = mysql_decode_row_prepare(client, buffer, client->response.packet_length);
        }
        else
        {
            //decode
            ret = mysql_decode_row(client, buffer, client->response.packet_length);
        }

        if (ret < 0)
        {
            break;
        }

        //next row
        client->response.num_row++;
        buffer += client->response.packet_length;
        n_buf -= client->response.packet_length;
        client->buffer->offset += client->response.packet_length + 4;
    }

    return SW_ERR;
}

static int mysql_decode_field(char *buf, int len, mysql_field *col)
{
    int i;
    ulong_t size;
    char nul;
    char *wh;
    int tmp_len;

    /**
     * string buffer
     */
    char *_buffer = (char*) emalloc(len);
    if (!_buffer)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    col->buffer = _buffer;

    wh = buf;

    i = 0;

    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->catalog_length = size;
    col->catalog = _buffer;
    _buffer += (size + 1);
    memcpy(col->catalog, &buf[i], size);
    col->catalog[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    db */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->db_length = size;
    col->db = _buffer;
    _buffer += (size + 1);
    memcpy(col->db, &buf[i], size);
    col->db[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    table */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->table_length = size;
    col->table = _buffer;
    _buffer += (size + 1);
    memcpy(col->table, &buf[i], size);
    col->table[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    org_table */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->org_table_length = size;
    col->org_table = _buffer;
    _buffer += (size + 1);
    memcpy(col->org_table, &buf[i], size);
    col->org_table[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    name */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->name_length = size;
    col->name = _buffer;
    _buffer += (size + 1);
    memcpy(col->name, &buf[i], size);
    col->name[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    org_name */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->org_name_length = size;
    col->org_name = _buffer;
    _buffer += (size + 1);
    memcpy(col->org_name, &buf[i], size);
    col->org_name[size] = '\0';
    wh += size + 1;
    i += size;

    /* check len */
    if (i + 13 > len)
    {
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }

    /* (filler) */
    i += 1;

    /* charset */
    col->charsetnr = mysql_uint2korr(&buf[i]);
    i += 2;

    /* length */
    col->length = mysql_uint4korr(&buf[i]);
    i += 4;

    /* type */
    col->type = (enum mysql_field_types) (uchar)buf[i];
    i += 1;

    /* flags */
    col->flags = mysql_uint2korr(&buf[i]);
    i += 2;

    /* decimals */
    col->decimals = buf[i];
    i += 1;

    /* filler */
    i += 2;

    /* default - a priori facultatif */
    if (len - i > 0)
    {
        tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
        if (tmp_len == -1)
        {
            return -SW_MYSQL_ERR_BAD_LCB;
        }
        i += tmp_len;
        if (i + size > len)
        {
            return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
        }
        col->def_length = size;
        col->def = _buffer;
        //_buffer += (size + 1);
        memcpy(col->def, &buf[i], size);
        col->def[size] = '\0';
        wh += size + 1;
        i += size;
    }
    else
    {
        col->def = NULL;
        col->def_length = 0;
    }

    /* set write pointer */
    return wh - buf;
}

static int mysql_read_columns(mysql_client *client)
{
    char *buffer = client->buffer->str + client->buffer->offset;
    uint32_t n_buf = client->buffer->length - client->buffer->offset;
    int ret;

    for (; client->response.index_column < client->response.num_column; client->response.index_column++)
    {
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "index_index_column=%d, n_buf=%d.", client->response.index_column, n_buf);

        if (n_buf < 4)
        {
            return SW_ERR;
        }

        client->response.packet_length = mysql_uint3korr(buffer);

        //no enough data
        if (n_buf - 4 < client->response.packet_length)
        {
            return SW_ERR;
        }

        client->response.packet_number = buffer[3];
        buffer += 4;
        n_buf -= 4;

        ret = mysql_decode_field(buffer, client->response.packet_length, &client->response.columns[client->response.index_column]);
        if (ret > 0)
        {
            buffer += client->response.packet_length;
            n_buf -= client->response.packet_length;
            client->buffer->offset += (client->response.packet_length + 4);
        }
        else
        {
            swWarn("mysql_decode_field failed, code=%d.", ret);
            break;
        }
    }

    if (mysql_read_eof(client, buffer, n_buf) < 0)
    {
        return SW_ERR;
    }

    buffer += 9;
    n_buf -= 9;

    if (client->cmd != SW_MYSQL_COM_STMT_PREPARE)
    {
        zval *result_array = client->response.result_array;
        if (!result_array)
        {
            SW_ALLOC_INIT_ZVAL(result_array);
            array_init(result_array);
            client->response.result_array = result_array;
        }
    }

    client->buffer->offset += buffer - (client->buffer->str + client->buffer->offset);

    return SW_OK;
}


int mysql_response(mysql_client *client)
{
    swString *buffer = client->buffer;

    char *p = buffer->str + buffer->offset;
    int ret;
    char nul;
    int n_buf = buffer->length - buffer->offset;

    while (n_buf > 0)
    {
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "client->state=%d, n_buf=%d.", client->state, n_buf);

        switch (client->state)
        {
        case SW_MYSQL_STATE_READ_START:
            if (buffer->length - buffer->offset < 5)
            {
                client->response.wait_recv = 1;
                return SW_ERR;
            }
            client->response.packet_length = mysql_uint3korr(p);
            client->response.packet_number = p[3];
            p += 4;
            n_buf -= 4;

            if (n_buf < client->response.packet_length)
            {
                client->response.wait_recv = 1;
                return SW_ERR;
            }

            client->response.response_type = p[0];
            p ++;
            n_buf --;

            /* error */
            if (client->response.response_type == 0xff)
            {
                client->response.error_code = mysql_uint2korr(p);
                /* status flag 1byte (#), skip.. */
                memcpy(client->response.status_msg, p + 3, 5);
                client->response.server_msg = p + 8;
                /**
                 * int<1> header  [ff] header of the ERR packet
                 * int<2>  error_code  error-code
                 * if capabilities & CLIENT_PROTOCOL_41 {
                 *  string[1] sql_state_marker    # marker of the SQL State
                 *  string[5] sql_state   SQL State
                 * }
                 */
                client->response.l_server_msg = client->response.packet_length - 9;
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* eof */
            else if (client->response.response_type == 0xfe)
            {
                client->response.warnings = mysql_uint2korr(p);
                client->response.status_code = mysql_uint2korr(p + 2);
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* ok */
            else if (client->response.response_type == 0)
            {
                if (client->cmd == SW_MYSQL_COM_STMT_PREPARE)
                {
                    ret = mysql_parse_prepare_result(client, p, n_buf);
                    if (ret < 0)
                    {
                        return SW_ERR;
                    }
                    else
                    {
                        p += ret;
                        n_buf -= ret;
                        buffer->offset += (5 + ret);
                        client->response.num_column = client->statement->field_count;
                        client->response.columns = ecalloc(client->response.num_column, sizeof(mysql_field));
                        if (client->statement->param_count > 0)
                        {
                            client->state = SW_MYSQL_STATE_READ_PARAM;
                        }
                        else
                        {
                            client->state = SW_MYSQL_STATE_READ_FIELD;
                        }
                        break;
                    }
                }
                /* affected rows */
                ret = mysql_length_coded_binary(p, &client->response.affected_rows, &nul, n_buf);
                n_buf -= ret;
                p += ret;

                /* insert id */
                ret = mysql_length_coded_binary(p, &client->response.insert_id, &nul, n_buf);
                n_buf -= ret;
                p += ret;

                /* server status */
                client->response.status_code = mysql_uint2korr(p);
                n_buf -= 2;
                p += 2;

                /* server warnings */
                client->response.warnings = mysql_uint2korr(p);

                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* result set */
            else
            {
                //Protocol::LengthEncodedInteger
                ret = mysql_length_coded_binary(p - 1, &client->response.num_column, &nul, n_buf + 1);
                if (ret < 0)
                {
                    return SW_ERR;
                }
                client->buffer->offset += (4 + ret);
                client->response.columns = ecalloc(client->response.num_column, sizeof(mysql_field));
                client->state = SW_MYSQL_STATE_READ_FIELD;
                break;
            }

        case SW_MYSQL_STATE_READ_FIELD:
            if (mysql_read_columns(client) < 0)
            {
                return SW_ERR;
            }
            else
            {
                if (client->cmd == SW_MYSQL_COM_STMT_PREPARE)
                {
                    mysql_columns_free(client);
                    return SW_OK;
                }
                client->state = SW_MYSQL_STATE_READ_ROW;
                break;
            }

        case SW_MYSQL_STATE_READ_ROW:
            if (mysql_read_rows(client) < 0)
            {
                return SW_ERR;
            }
            else
            {
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }

        case SW_MYSQL_STATE_READ_PARAM:
            if (mysql_read_params(client) < 0)
            {
                return SW_ERR;
            }
            else if (client->statement->field_count > 0)
            {
                client->state = SW_MYSQL_STATE_READ_FIELD;
                continue;
            }
            else
            {
                mysql_columns_free(client);
                return SW_OK;
            }

        default:
            return SW_ERR;
        }
    }

    return SW_OK;
}

int mysql_query(zval *zobject, mysql_client *client, swString *sql, zval *callback TSRMLS_DC)
{
    if (!client->cli)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed.", client->fd);
        return SW_ERR;
    }
    if (!client->connected)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        swoole_php_error(E_WARNING, "mysql client is not connected to server.");
        return SW_ERR;
    }
    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query.");
        return SW_ERR;
    }

    if (callback != NULL)
    {
        sw_zval_add_ref(&callback);
        client->callback = sw_zval_dup(callback);
    }

    client->cmd = SW_MYSQL_COM_QUERY;

    swString_clear(mysql_request_buffer);

    if (mysql_request(sql, mysql_request_buffer) < 0)
    {
        return SW_ERR;
    }
    //send query
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_update_property_bool(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("errno"), 2006 TSRMLS_CC);
        }
        return SW_ERR;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        return SW_OK;
    }
}

#ifdef SW_MYSQL_DEBUG

void mysql_client_info(mysql_client *client)
{
    printf("\n"SW_START_LINE"\nmysql_client\nbuffer->offset=%ld\nbuffer->length=%ld\nstatus=%d\n"
            "packet_length=%d\npacket_number=%d\n"
            "insert_id=%d\naffected_rows=%d\n"
            "warnings=%d\n"SW_END_LINE, client->buffer->offset, client->buffer->length, client->response.status_code,
            client->response.packet_length, client->response.packet_number,
            client->response.insert_id, client->response.affected_rows,
            client->response.warnings);
    int i;

    if (client->response.num_column)
    {
        for (i = 0; i < client->response.num_column; i++)
        {
            mysql_column_info(&client->response.columns[i]);
        }
    }
}

void mysql_column_info(mysql_field *field)
{
    printf("\n"SW_START_LINE"\nname=%s, table=%s, db=%s\n"
            "name_length=%d, table_length=%d, db_length=%d\n"
            "catalog=%s, default_value=%s\n"
            "length=%ld, type=%d\n"SW_END_LINE,
            field->name, field->table, field->db,
            field->name_length, field->table_length, field->db_length,
            field->catalog, field->def,
            field->length, field->type
           );
}

#endif

static PHP_METHOD(swoole_mysql, __construct)
{
    if (!mysql_request_buffer)
    {
        mysql_request_buffer = swString_new(SW_MYSQL_QUERY_INIT_SIZE);
        if (!mysql_request_buffer)
        {
            swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
            RETURN_FALSE;
        }
    }

    mysql_client *client = emalloc(sizeof(mysql_client));
    bzero(client, sizeof(mysql_client));
    swoole_set_object(getThis(), client);
}

static PHP_METHOD(swoole_mysql, connect)
{
    zval *server_info;
    zval *callback;
    char buf[2048];

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "az", &server_info, &callback) == FAILURE)
    {
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (client->cli)
    {
        swoole_php_error(E_WARNING, "The mysql client is already connected server.");
        RETURN_FALSE;
    }

    php_swoole_array_separate(server_info);

    HashTable *_ht = Z_ARRVAL_P(server_info);
    zval *value;

    mysql_connector *connector = &client->connector;

    if (php_swoole_array_get_value(_ht, "host", value))
    {
        convert_to_string(value);
        connector->host = Z_STRVAL_P(value);
        connector->host_len = Z_STRLEN_P(value);
    }
    else
    {
        zend_throw_exception(swoole_mysql_exception_class_entry_ptr, "HOST parameter is required.", 11 TSRMLS_CC);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "port", value))
    {
        convert_to_long(value);
        connector->port = Z_LVAL_P(value);
    }
    else
    {
        connector->port = SW_MYSQL_DEFAULT_PORT;
    }
    if (php_swoole_array_get_value(_ht, "user", value))
    {
        convert_to_string(value);
        connector->user = Z_STRVAL_P(value);
        connector->user_len = Z_STRLEN_P(value);
    }
    else
    {
        zend_throw_exception(swoole_mysql_exception_class_entry_ptr, "USER parameter is required.", 11 TSRMLS_CC);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "password", value))
    {
        convert_to_string(value);
        connector->password = Z_STRVAL_P(value);
        connector->password_len = Z_STRLEN_P(value);
    }
    else
    {
        zend_throw_exception(swoole_mysql_exception_class_entry_ptr, "PASSWORD parameter is required.", 11 TSRMLS_CC);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "database", value))
    {
        convert_to_string(value);
        connector->database = Z_STRVAL_P(value);
        connector->database_len = Z_STRLEN_P(value);
    }
    else
    {
        zend_throw_exception(swoole_mysql_exception_class_entry_ptr, "DATABASE parameter is required.", 11 TSRMLS_CC);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "timeout", value))
    {
        convert_to_double(value);
        connector->timeout = Z_DVAL_P(value);
    }
    else
    {
        connector->timeout = SW_MYSQL_CONNECT_TIMEOUT;
    }
    if (php_swoole_array_get_value(_ht, "charset", value))
    {
        convert_to_string(value);
        connector->character_set = mysql_get_charset(Z_STRVAL_P(value));
        if (connector->character_set < 0)
        {
            snprintf(buf, sizeof(buf), "unknown charset [%s].", Z_STRVAL_P(value));
            zend_throw_exception(swoole_mysql_exception_class_entry_ptr, buf, 11 TSRMLS_CC);
            RETURN_FALSE;
        }
    }
    //use the server default charset.
    else
    {
        connector->character_set = 0;
    }

    if (php_swoole_array_get_value(_ht, "strict_type", value))
    {
#if PHP_MAJOR_VERSION < 7
        if (Z_TYPE_P(value) == IS_BOOL && Z_BVAL_P(value) == 1)
#else
        if (Z_TYPE_P(value) == IS_TRUE)
#endif
        {
            connector->strict_type = 1;
        }
        else
        {
            connector->strict_type = 0;
        }
    }
    else
    {
        connector->strict_type = 0;
    }

    swClient *cli = emalloc(sizeof(swClient));
    int type = SW_SOCK_TCP;

    if (strncasecmp(connector->host, ZEND_STRL("unix:/")) == 0)
    {
        connector->host = connector->host + 5;
        connector->host_len = connector->host_len - 5;
        type = SW_SOCK_UNIX_STREAM;
    }
    else if (strchr(connector->host, ':'))
    {
        type = SW_SOCK_TCP6;
    }

    php_swoole_check_reactor();
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ, swoole_mysql_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_WRITE, swoole_mysql_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_ERROR, swoole_mysql_onError);
    }
    //create socket
    if (swClient_create(cli, type, 0) < 0)
    {
        zend_throw_exception(swoole_mysql_exception_class_entry_ptr, "swClient_create failed.", 1 TSRMLS_CC);
        RETURN_FALSE;
    }
    //tcp nodelay
    if (type != SW_SOCK_UNIX_STREAM)
    {
        int tcp_nodelay = 1;
        if (setsockopt(cli->socket->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) == -1)
        {
            swoole_php_sys_error(E_WARNING, "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY) failed.", cli->socket->fd);
        }
    }
    //connect to mysql server
    int ret = cli->connect(cli, connector->host, connector->port, connector->timeout, 1);
    if ((ret < 0 && errno == EINPROGRESS) || ret == 0)
    {
        if (connector->timeout > 0)
        {
            php_swoole_check_timer((int) (connector->timeout * 1000));
            cli->timer = SwooleG.timer.add(&SwooleG.timer, (int) (connector->timeout * 1000), 0, client, swoole_mysql_onTimeout);
            cli->timeout = connector->timeout;
        }
        if (SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, PHP_SWOOLE_FD_MYSQL | SW_EVENT_WRITE) < 0)
        {
            RETURN_FALSE;
        }
    }
    else
    {
        snprintf(buf, sizeof(buf), "connect to mysql server[%s:%d] failed.", connector->host, connector->port);
        zend_throw_exception(swoole_mysql_exception_class_entry_ptr, buf, 2 TSRMLS_CC);
        RETURN_FALSE;
    }

    zend_update_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("onConnect"), callback TSRMLS_CC);
    zend_update_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("serverInfo"), server_info TSRMLS_CC);
    zend_update_property_long(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

    client->buffer = swString_new(SW_BUFFER_SIZE_BIG);
    client->fd = cli->socket->fd;
    client->object = getThis();
    client->cli = cli;
    sw_copy_to_stack(client->object, client->_object);
    sw_zval_add_ref(&client->object);
    sw_zval_ptr_dtor(&server_info);

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, cli->socket->fd);
    _socket->object = client;
    _socket->active = 0;

    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql, query)
{
    zval *callback;
    swString sql;
    bzero(&sql, sizeof(sql));

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &sql.str, &sql.length, &callback) == FAILURE)
    {
        return;
    }

    if (!php_swoole_is_callable(callback TSRMLS_CC))
    {
        RETURN_FALSE;
    }

    if (sql.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty.");
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(mysql_query(getThis(), client, &sql, callback TSRMLS_CC));
}

static PHP_METHOD(swoole_mysql, begin)
{
    zval *callback;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &callback) == FAILURE)
    {
        return;
    }

    if (!php_swoole_is_callable(callback TSRMLS_CC))
    {
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }
    if (client->transaction)
    {
        zend_throw_exception(swoole_mysql_exception_class_entry_ptr, "There is already an active transaction.", 21 TSRMLS_CC);
        RETURN_FALSE;
    }

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, ZEND_STRL("START TRANSACTION"));
    if (mysql_query(getThis(), client, &sql, callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        client->transaction = 1;
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_mysql, commit)
{
    zval *callback;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &callback) == FAILURE)
    {
        return;
    }

    if (!php_swoole_is_callable(callback TSRMLS_CC))
    {
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }
    if (!client->transaction)
    {
        zend_throw_exception(swoole_mysql_exception_class_entry_ptr, "There is no active transaction.", 22 TSRMLS_CC);
        RETURN_FALSE;
    }

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, ZEND_STRL("COMMIT"));
    if (mysql_query(getThis(), client, &sql, callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        client->transaction = 0;
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_mysql, rollback)
{
    zval *callback;
    if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &callback) == FAILURE)
    {
        return;
    }

    if (!php_swoole_is_callable(callback TSRMLS_CC))
    {
        RETURN_FALSE;
    }


    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }
    if (!client->transaction)
    {
        zend_throw_exception(swoole_mysql_exception_class_entry_ptr, "There is no active transaction.", 22 TSRMLS_CC);
        RETURN_FALSE;
    }

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, ZEND_STRL("ROLLBACK"));
    if (mysql_query(getThis(), client, &sql, callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        client->transaction = 0;
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_mysql, __destruct)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        return;
    }
    if (client->state != SW_MYSQL_STATE_CLOSED && client->cli)
    {
        zval *retval = NULL;
        zval *zobject = getThis();
        client->cli->destroyed = 1;
        sw_zend_call_method_with_0_params(&zobject, swoole_mysql_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    //release buffer memory
    if (client->buffer)
    {
        swString_free(client->buffer);
    }
    efree(client);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_mysql, close)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }

    if (!client->cli)
    {
        RETURN_FALSE;
    }

    if (client->cli->socket->closing)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SESSION_CLOSING, "The mysql connection[%d] is closing.", client->fd);
        RETURN_FALSE;
    }

    zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connected"), 0 TSRMLS_CC);
    SwooleG.main_reactor->del(SwooleG.main_reactor, client->fd);

    swConnection *socket = swReactor_get(SwooleG.main_reactor, client->fd);
    bzero(socket, sizeof(swConnection));
    socket->removed = 1;

    zend_bool is_destroyed = client->cli->destroyed;

    zval *retval = NULL;
    zval **args[1];
    zval *object = getThis();
    if (client->onClose)
    {
        client->cli->socket->closing = 1;
        args[0] = &object;
        if (sw_call_user_function_ex(EG(function_table), NULL, client->onClose, &retval, 1, args, 0, NULL TSRMLS_CC) != SUCCESS)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_mysql onClose callback error.");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
    mysql_client_free(client, getThis());
    if (!is_destroyed)
    {
        sw_zval_ptr_dtor(&object);
    }
}

static PHP_METHOD(swoole_mysql, on)
{
    char *name;
    zend_size_t len;
    zval *cb;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &name, &len, &cb) == FAILURE)
    {
        return;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }

    if (strncasecmp("close", name, len) == 0)
    {
        zend_update_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("onClose"), cb TSRMLS_CC);
        client->onClose = sw_zend_read_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("onClose"), 0 TSRMLS_CC);
        sw_copy_to_stack(client->onClose, client->_onClose);
    }
    else
    {
        swoole_php_error(E_WARNING, "Unknown event type[%s]", name);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql, getState)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }
    RETURN_LONG(client->state);
}

static void swoole_mysql_onTimeout(swTimer *timer, swTimer_node *tnode)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
    mysql_client *client = tnode->data;
    client->connector.error_code = ETIMEDOUT;
    client->connector.error_msg = strerror(client->connector.error_code);
    client->connector.error_length = strlen(client->connector.error_msg);
    swoole_mysql_onConnect(client TSRMLS_CC);
}

static int swoole_mysql_onError(swReactor *reactor, swEvent *event)
{
    swClient *cli = event->socket->object;
    if (cli && cli->socket && cli->socket->active)
    {
#if PHP_MAJOR_VERSION < 7
        TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif
        mysql_client *client = event->socket->object;
        if (!client)
        {
            close(event->fd);
            return SW_ERR;
        }
        zval *retval = NULL;
        zval *zobject = client->object;
        sw_zend_call_method_with_0_params(&zobject, swoole_mysql_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
        return SW_OK;
    }
    else
    {
        return swoole_mysql_onWrite(reactor, event);
    }
}

static void swoole_mysql_onConnect(mysql_client *client TSRMLS_DC)
{
    zval *zobject = client->object;
    zval *callback = sw_zend_read_property(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("onConnect"), 0 TSRMLS_CC);

    zval *retval = NULL;
    zval *result;
    zval **args[2];

    SW_MAKE_STD_ZVAL(result);

    if (client->cli->timer)
    {
        swTimer_del(&SwooleG.timer, client->cli->timer);
        client->cli->timer = NULL;
    }

    if (client->connector.error_code > 0)
    {
        zend_update_property_stringl(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connect_error"), client->connector.error_msg, client->connector.error_length TSRMLS_CC);
        zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), client->connector.error_code TSRMLS_CC);
        ZVAL_BOOL(result, 0);
    }
    else
    {
        zend_update_property_bool(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connected"), 1 TSRMLS_CC);
        ZVAL_BOOL(result, 1);
        client->connected = 1;
    }

    args[0] = &zobject;
    args[1] = &result;

    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_mysql onConnect handler error.");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval != NULL)
    {
        sw_zval_ptr_dtor(&retval);
    }
    sw_zval_ptr_dtor(&result);
    if (client->connector.error_code > 0)
    {
        retval = NULL;
        //close
        sw_zend_call_method_with_0_params(&zobject, swoole_mysql_class_entry_ptr, NULL, "close", &retval);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
}

static int swoole_mysql_onWrite(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    if (event->socket->active)
    {
        return swReactor_onWrite(SwooleG.main_reactor, event);
    }

    socklen_t len = sizeof(SwooleG.error);
    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &SwooleG.error, &len) < 0)
    {
        swWarn("getsockopt(%d) failed. Error: %s[%d]", event->fd, strerror(errno), errno);
        return SW_ERR;
    }

    mysql_client *client = event->socket->object;
    //success
    if (SwooleG.error == 0)
    {
        //listen read event
        SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ);
        //connected
        event->socket->active = 1;
        client->handshake = SW_MYSQL_HANDSHAKE_WAIT_REQUEST;
    }
    else
    {
        client->connector.error_code = SwooleG.error;
        client->connector.error_msg = strerror(SwooleG.error);
        client->connector.error_length = strlen(client->connector.error_msg);
        swoole_mysql_onConnect(client TSRMLS_CC);
    }
    return SW_OK;
}

static int swoole_mysql_onHandShake(mysql_client *client TSRMLS_DC)
{
    swString *buffer = client->buffer;
    swClient *cli = client->cli;
    mysql_connector *connector = &client->connector;

    int n = cli->recv(cli, buffer->str + buffer->length, buffer->size - buffer->length, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("Read from socket[%d] failed.", cli->socket->fd);
            return SW_ERR;
        case SW_CLOSE:
            goto system_call_error;
        case SW_WAIT:
            return SW_OK;
        default:
            return SW_ERR;
        }
    }
    else if (n == 0)
    {
        errno = ECONNRESET;
        goto system_call_error;
    }

    buffer->length += n;

    int ret;
    if (client->handshake == SW_MYSQL_HANDSHAKE_WAIT_REQUEST)
    {
        ret = mysql_handshake(connector, buffer->str, buffer->length);
        if (ret < 0)
        {
            swoole_mysql_onConnect(client TSRMLS_CC);
        }
        else if (ret > 0)
        {
            if (cli->send(cli, connector->buf, connector->packet_length + 4, 0) < 0)
            {
                system_call_error: connector->error_code = errno;
                connector->error_msg = strerror(errno);
                connector->error_length = strlen(connector->error_msg);
                swoole_mysql_onConnect(client TSRMLS_CC);
                return SW_OK;
            }
            else
            {
                swString_clear(buffer);
                client->handshake = SW_MYSQL_HANDSHAKE_WAIT_RESULT;
            }
        }
    }
    else
    {
        ret = mysql_get_result(connector, buffer->str, buffer->length);
        if (ret < 0)
        {
            swoole_mysql_onConnect(client TSRMLS_CC);
        }
        else if (ret > 0)
        {
            swString_clear(buffer);
            client->handshake = SW_MYSQL_HANDSHAKE_COMPLETED;
            swoole_mysql_onConnect(client TSRMLS_CC);
        }
    }
    return SW_OK;
}

static int swoole_mysql_onRead(swReactor *reactor, swEvent *event)
{
#if PHP_MAJOR_VERSION < 7
    TSRMLS_FETCH_FROM_CTX(sw_thread_ctx ? sw_thread_ctx : NULL);
#endif

    mysql_client *client = event->socket->object;
    if (client->handshake != SW_MYSQL_HANDSHAKE_COMPLETED)
    {
        return swoole_mysql_onHandShake(client TSRMLS_CC);
    }

    int sock = event->fd;
    int ret;

    zval *zobject = client->object;
    swString *buffer = client->buffer;

    zval **args[2];
    zval *callback = NULL;
    zval *retval = NULL;
    zval *result = NULL;

    while(1)
    {
        ret = recv(sock, buffer->str + buffer->length, buffer->size - buffer->length, 0);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                switch (swConnection_error(errno))
                {
                case SW_ERROR:
                    swSysError("Read from socket[%d] failed.", event->fd);
                    return SW_ERR;
                case SW_CLOSE:
                    goto close_fd;
                case SW_WAIT:
                    goto parse_response;
                default:
                    return SW_ERR;
                }
            }
        }
        else if (ret == 0)
        {
            close_fd:
            if (client->state == SW_MYSQL_STATE_READ_END)
            {
                goto parse_response;
            }
            sw_zend_call_method_with_0_params(&zobject, swoole_mysql_class_entry_ptr, NULL, "close", &retval);
            if (retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
            return SW_OK;
        }
        else
        {
            buffer->length += ret;
            //recv again
            if (buffer->length == buffer->size)
            {
                if (swString_extend(buffer, buffer->size * 2) < 0)
                {
                    swoole_php_fatal_error(E_ERROR, "malloc failed.");
                    reactor->del(SwooleG.main_reactor, event->fd);
                }
                continue;
            }

            parse_response:
            if (mysql_response(client) < 0)
            {
                return SW_OK;
            }

            zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("affected_rows"), client->response.affected_rows TSRMLS_CC);
            zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("insert_id"), client->response.insert_id TSRMLS_CC);
            client->state = SW_MYSQL_STATE_QUERY;

            args[0] = &zobject;

            //OK
            if (client->response.response_type == 0)
            {
                SW_ALLOC_INIT_ZVAL(result);
                ZVAL_BOOL(result, 1);
            }
            //ERROR
            else if (client->response.response_type == 255)
            {
                SW_ALLOC_INIT_ZVAL(result);
                ZVAL_BOOL(result, 0);

                zend_update_property_stringl(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("error"), client->response.server_msg, client->response.l_server_msg TSRMLS_CC);
                zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("errno"), client->response.error_code TSRMLS_CC);
            }
            //ResultSet
            else
            {
                result = client->response.result_array;
            }

            args[1] = &result;
            callback = client->callback;
            if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
            {
                swoole_php_fatal_error(E_WARNING, "swoole_async_mysql callback[2] handler error.");
                reactor->del(SwooleG.main_reactor, event->fd);
            }
            if (EG(exception))
            {
                zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
            }
            /* free memory */
            if (retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
            if (result)
            {
                sw_zval_free(result);
            }
            //free callback object
            sw_zval_free(callback);
            swConnection *_socket = swReactor_get(SwooleG.main_reactor, event->fd);
            if (_socket->object)
            {
                //clear buffer
                swString_clear(client->buffer);
                bzero(&client->response, sizeof(client->response));
            }
            return SW_OK;
        }
    }
    return SW_OK;
}

#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql, escape)
{
    swString str;
    bzero(&str, sizeof(str));
    long flags;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &str.str, &str.length, &flags) == FAILURE)
    {
        return;
    }

    if (str.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "String is empty.");
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }
    if (!client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed.", client->fd);
        RETURN_FALSE;
    }

    char *newstr = safe_emalloc(2, str.length + 1, 1);
    if (newstr == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "emalloc(%ld) failed.", str.length + 1);
        RETURN_FALSE;
    }

    const MYSQLND_CHARSET* cset = mysqlnd_find_charset_nr(client->connector.character_set);
    if (cset == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "unknown mysql charset[%s].", client->connector.character_set);
        RETURN_FALSE;
    }
    int newstr_len = mysqlnd_cset_escape_slashes(cset, newstr, str.str, str.length TSRMLS_CC);
    if (newstr_len < 0)
    {
        swoole_php_fatal_error(E_ERROR, "mysqlnd_cset_escape_slashes() failed.");
        RETURN_FALSE;
    }
    SW_RETURN_STRINGL(newstr, newstr_len, 0);
}
#endif

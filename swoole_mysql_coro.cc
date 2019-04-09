/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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

#include "php_swoole_cxx.h"

#include "swoole_coroutine.h"
#include "swoole_mysql_coro.h"

#include "error.h"

// see mysqlnd 'L64' macro redefined
#undef L64

extern "C" {
#include "ext/hash/php_hash.h"
#include "ext/hash/php_hash_sha.h"
#include "ext/standard/php_math.h"
#include "ext/standard/php_string.h"

#ifdef SW_MYSQL_RSA_SUPPORT
#include <openssl/rsa.h>
#include <openssl/pem.h>
#endif
}

using namespace swoole;

static PHP_METHOD(swoole_mysql_coro, __construct);
static PHP_METHOD(swoole_mysql_coro, __destruct);
static PHP_METHOD(swoole_mysql_coro, connect);
static PHP_METHOD(swoole_mysql_coro, query);
static PHP_METHOD(swoole_mysql_coro, recv);
static PHP_METHOD(swoole_mysql_coro, nextResult);
#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql_coro, escape);
#endif
static PHP_METHOD(swoole_mysql_coro, begin);
static PHP_METHOD(swoole_mysql_coro, commit);
static PHP_METHOD(swoole_mysql_coro, rollback);
static PHP_METHOD(swoole_mysql_coro, prepare);
static PHP_METHOD(swoole_mysql_coro, setDefer);
static PHP_METHOD(swoole_mysql_coro, getDefer);
static PHP_METHOD(swoole_mysql_coro, close);

static PHP_METHOD(swoole_mysql_coro, select);
static PHP_METHOD(swoole_mysql_coro, insert);
static PHP_METHOD(swoole_mysql_coro, replace);
static PHP_METHOD(swoole_mysql_coro, update);
static PHP_METHOD(swoole_mysql_coro, delete);

static PHP_METHOD(swoole_mysql_coro_statement, __destruct);
static PHP_METHOD(swoole_mysql_coro_statement, execute);
static PHP_METHOD(swoole_mysql_coro_statement, fetch);
static PHP_METHOD(swoole_mysql_coro_statement, fetchAll);
static PHP_METHOD(swoole_mysql_coro_statement, nextResult);

#define UTF8_MB4 "utf8mb4"
#define UTF8_MB3 "utf8"

#define DATETIME_MAX_SIZE  32

typedef struct _mysql_big_data_info {
    // for used:
    ulong_t len;  // data length
    ulong_t remaining_size; // max remaining size that can be read
    uint32_t currrent_packet_remaining_size; // remaining size of current packet
    char *read_p; // where to start reading data
    // for result:
    uint32_t ext_header_len; // extra packet header length
    uint32_t ext_packet_len; // extra packet length (body only)
} mysql_big_data_info;

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_connect, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, server_config, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_query, 0, 0, 1)
    ZEND_ARG_INFO(0, sql)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_begin, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_commit, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_rollback, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_prepare, 0, 0, 1)
    ZEND_ARG_INFO(0, statement)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_setDefer, 0, 0, 0)
    ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_select, 0, 0, 2)
ZEND_ARG_INFO(0, table)
ZEND_ARG_INFO(0, join)
ZEND_ARG_INFO(0, columns)
ZEND_ARG_INFO(0, where)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_insert, 0, 0, 2)
ZEND_ARG_INFO(0, table)
ZEND_ARG_ARRAY_INFO(0, data, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_replace, 0, 0, 2)
ZEND_ARG_INFO(0, table)
ZEND_ARG_ARRAY_INFO(0, data, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_update, 0, 0, 2)
ZEND_ARG_INFO(0, table)
ZEND_ARG_ARRAY_INFO(0, data, 0)
ZEND_ARG_INFO(0, where)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_delete, 0, 0, 1)
ZEND_ARG_INFO(0, table)
ZEND_ARG_INFO(0, where)
ZEND_END_ARG_INFO()

#ifdef SW_USE_MYSQLND
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_escape, 0, 0, 1)
    ZEND_ARG_INFO(0, string)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_execute, 0, 0, 0)
    ZEND_ARG_INFO(0, params)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_fetch, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_fetchAll, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_nextResult, 0, 0, 0)
ZEND_END_ARG_INFO()

static zend_class_entry *swoole_mysql_coro_ce;
static zend_object_handlers swoole_mysql_coro_handlers;

static zend_class_entry *swoole_mysql_coro_exception_ce;
static zend_object_handlers swoole_mysql_coro_exception_handlers;

static zend_class_entry *swoole_mysql_coro_statement_ce;
static zend_object_handlers swoole_mysql_coro_statement_handlers;

static const zend_function_entry swoole_mysql_coro_methods[] =
{
    PHP_ME(swoole_mysql_coro, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, connect, arginfo_swoole_mysql_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, query, arginfo_swoole_mysql_coro_query, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, recv, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, nextResult, arginfo_swoole_void, ZEND_ACC_PUBLIC)
#ifdef SW_USE_MYSQLND
    PHP_ME(swoole_mysql_coro, escape, arginfo_swoole_mysql_coro_escape, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_mysql_coro, begin, arginfo_swoole_mysql_coro_begin, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, commit, arginfo_swoole_mysql_coro_commit, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, rollback, arginfo_swoole_mysql_coro_rollback, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, prepare, arginfo_swoole_mysql_coro_prepare, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, setDefer, arginfo_swoole_mysql_coro_setDefer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, getDefer, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    
    PHP_ME(swoole_mysql_coro, select, arginfo_swoole_mysql_coro_select, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, insert, arginfo_swoole_mysql_coro_insert, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, replace, arginfo_swoole_mysql_coro_replace, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, update, arginfo_swoole_mysql_coro_update, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, delete, arginfo_swoole_mysql_coro_delete, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_mysql_coro_statement_methods[] =
{
    PHP_ME(swoole_mysql_coro_statement, execute, arginfo_swoole_mysql_coro_statement_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, fetch, arginfo_swoole_mysql_coro_statement_fetch, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, fetchAll, arginfo_swoole_mysql_coro_statement_fetchAll, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, nextResult, arginfo_swoole_mysql_coro_statement_nextResult, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static int swoole_mysql_coro_onRead(swReactor *reactor, swEvent *event);
static int swoole_mysql_coro_onWrite(swReactor *reactor, swEvent *event);
static int swoole_mysql_coro_onError(swReactor *reactor, swEvent *event);
static void swoole_mysql_coro_onConnect(mysql_client *client);
static void swoole_mysql_coro_onConnectTimeout(swTimer *timer, swTimer_node *tnode);
static void swoole_mysql_coro_onTimeout(swTimer *timer, swTimer_node *tnode);
static int mysql_query(zval *zobject, mysql_client *client, swString *sql, zval *callback);
static int mysql_response(mysql_client *client);
static int mysql_is_over(mysql_client *client);

static void swoole_mysql_coro_free_object(zend_object *object);

static zend_object *swoole_mysql_coro_create_object(zend_class_entry *ce)
{
    zend_object *object;
    object = zend_objects_new(ce);
    object->handlers = &swoole_mysql_coro_handlers;
    object_properties_init(object, ce);

    mysql_client *client = (mysql_client *) emalloc(sizeof(mysql_client));
    bzero(client, sizeof(mysql_client));
    swoole_set_object_by_handle(object->handle, client);

    return object;
}

void swoole_mysql_coro_init(int module_number)
{
    SW_INIT_CLASS_ENTRY(swoole_mysql_coro, "Swoole\\Coroutine\\MySQL", NULL, "Co\\MySQL", swoole_mysql_coro_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_mysql_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_mysql_coro, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_mysql_coro, zend_class_unset_property_deny);
    SW_SET_CLASS_CREATE_AND_FREE(swoole_mysql_coro, swoole_mysql_coro_create_object, swoole_mysql_coro_free_object);

    SW_INIT_CLASS_ENTRY(swoole_mysql_coro_statement, "Swoole\\Coroutine\\MySQL\\Statement", NULL, "Co\\MySQL\\Statement", swoole_mysql_coro_statement_methods);
    SW_SET_CLASS_SERIALIZABLE(swoole_mysql_coro_statement, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_mysql_coro_statement, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_mysql_coro_statement, zend_class_unset_property_deny);

    SW_INIT_CLASS_ENTRY_EX(swoole_mysql_coro_exception, "Swoole\\Coroutine\\MySQL\\Exception", NULL, "Co\\MySQL\\Exception", NULL, swoole_exception);
    SW_SET_CLASS_SERIALIZABLE(swoole_mysql_coro_exception, zend_class_serialize_deny, zend_class_unserialize_deny);
    SW_SET_CLASS_CLONEABLE(swoole_mysql_coro_exception, zend_class_clone_deny);
    SW_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_mysql_coro_exception, zend_class_unset_property_deny);

    zend_declare_property_string(swoole_mysql_coro_ce, ZEND_STRL("serverInfo"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_mysql_coro_ce, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_mysql_coro_ce, ZEND_STRL("connect_error"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("connect_errno"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("affected_rows"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("insert_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_mysql_coro_ce, ZEND_STRL("error"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce, ZEND_STRL("errno"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_long(swoole_mysql_coro_statement_ce, ZEND_STRL("affected_rows"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_statement_ce, ZEND_STRL("insert_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_mysql_coro_statement_ce, ZEND_STRL("error"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_statement_ce, ZEND_STRL("errno"), 0, ZEND_ACC_PUBLIC);
}


static sw_inline int mysql_read_err(mysql_client *client, char *buf, int n_buf)
{
    // not ERR packet
    if ((uint8_t) buf[4] != SW_MYSQL_PACKET_ERR)
    {
        return SW_ERR;
    }

    swMysqlPacketDump(buf, SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length, "ERR_Packet");

    client->response.response_type = SW_MYSQL_PACKET_ERR;

    // ERR Packet = Packet header (4 bytes) + ERR Payload

    // skip packet header
    buf += SW_MYSQL_PACKET_HEADER_SIZE;

    // int<1>   header  [ff] header of the ERR packet
    buf += 1;

    // int<2>   error_code  error-code
    client->response.error_code = mysql_uint2korr(buf);
    buf += 2;

    // string[1]    sql_state_marker    # marker of the SQL State
    buf += 1;

    // string[5]    sql_state   SQL State
    memcpy(client->response.status_msg, buf, 5);
    buf += 5;

    // string<EOF>  error_message   human readable error message
    client->response.server_msg = buf;
    client->response.l_server_msg = client->response.packet_length - 9;
    MYSQL_RESPONSE_BUFFER->offset += SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length;

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "ERR_Packet, error_code=%u, status_msg=%s", client->response.error_code, client->response.status_msg);

    return SW_OK;
}

static sw_inline int mysql_read_ok(mysql_client *client, char *buf, int n_buf)
{
    int ret;
    char nul;

    if ((uint8_t) buf[4] != SW_MYSQL_PACKET_OK || client->cmd == SW_MYSQL_COM_STMT_PREPARE)
    {
        return SW_ERR;
    }

    swMysqlPacketDump(buf, SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length, "OK_Packet");

    // skip packet header
    buf += SW_MYSQL_PACKET_HEADER_SIZE;
    n_buf -= SW_MYSQL_PACKET_HEADER_SIZE;

    // int<1>   header  [00] or [fe] the OK packet header
    buf += 1;
    n_buf -= 1;

    // int<lenenc>  affected_rows   affected rows
    ret = mysql_length_coded_binary(buf, &client->response.affected_rows, &nul, n_buf);
    n_buf -= ret;
    buf += ret;

    // int<lenenc>  last_insert_id  last insert-id
    ret = mysql_length_coded_binary(buf, &client->response.insert_id, &nul, n_buf);
    n_buf -= ret;
    buf += ret;

    // int<2>   status_flags    Status Flags
    client->response.status_code = mysql_uint2korr(buf);
    buf += 2;

    // int<2>   warnings    number of warnings
    client->response.warnings = mysql_uint2korr(buf);

    MYSQL_RESPONSE_BUFFER->offset += SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length;

    swTraceLog(
        SW_TRACE_MYSQL_CLIENT, "OK_Packet, affected_rows=%lu, insert_id=%lu, status_flags=%u, warnings=%u",
        client->response.affected_rows, client->response.insert_id, client->response.status_code, client->response.warnings
    );

    return SW_OK;
}


static zend_string* mysql_decode_big_data(mysql_big_data_info *mbdi)
{
    // through ext_packet_num to calc read_n += ?
    mbdi->ext_header_len = SW_MYSQL_PACKET_HEADER_SIZE * (((mbdi->len - mbdi->currrent_packet_remaining_size) / SW_MYSQL_MAX_PACKET_BODY_SIZE) + 1);
    if (mbdi->ext_header_len + mbdi->len > mbdi->remaining_size)
    {
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "big packet need %lu, but only %lu", mbdi->ext_header_len + mbdi->len, mbdi->remaining_size);
        return NULL;
    }
    else
    {
        // optimization: allocate a complete piece of memory at once
        zend_string* zstring = zend_string_alloc(mbdi->len, 0);;
        size_t write_s = 0, write_n = 0;
        char *read_p, *write_p;
        read_p = mbdi->read_p;
        write_p = ZSTR_VAL(zstring);
        // copy the remaining data of the current packet
        write_s = mbdi->currrent_packet_remaining_size;
        memcpy(write_p, read_p, write_s);
        read_p += write_s;
        write_p += write_s;
        write_n += write_s;
        while (write_n < mbdi->len) // copy the next... packet
        {
            uint32_t _packet_len = mysql_uint3korr(read_p);
            mbdi->ext_packet_len += _packet_len;
            write_s = MIN(_packet_len, mbdi->len - write_n);
            memcpy(write_p, read_p + SW_MYSQL_PACKET_HEADER_SIZE, write_s);
            read_p += SW_MYSQL_PACKET_HEADER_SIZE + write_s;
            write_p += write_s;
            write_n += write_s;
        }
        ZSTR_VAL(zstring)[mbdi->len] = '\0';
        SW_ASSERT(ZSTR_VAL(zstring) + mbdi->len == write_p);
        return zstring;
    }
}

static ssize_t mysql_decode_row(mysql_client *client, char *buf, uint32_t packet_length, size_t n_buf)
{
    uint32_t i;
    int tmp_len;
    ulong_t len;
    char nul;
    mysql_row row;
    char value_buffer[32];
    char *error;
    ssize_t read_n = 0;
    zend_string *zstring = NULL;
    zval *result_array = client->response.result_array;
    zval *row_array = sw_malloc_zval();

    bzero(&row, sizeof(row));
    array_init(row_array);

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "mysql_decode_row begin, num_column=%ld, packet_length=%u", client->response.num_column, packet_length);

    mysql_field *field = NULL;

    for (i = 0; i < client->response.num_column; i++)
    {
        tmp_len = mysql_length_coded_binary(&buf[read_n], &len, &nul, packet_length - read_n);
        if (tmp_len == -1)
        {
            swWarn("mysql response parse error: bad lcb, tmp_len=%d", tmp_len);
            read_n = -SW_MYSQL_ERR_BAD_LCB;
            goto _error;
        }
        read_n += tmp_len;

        // WARNING: data may be longer than single packet (0x00fffff => 16M)
        if (unlikely(len > (uint32_t) (packet_length - read_n)))
        {
            mysql_big_data_info mbdi = { len, n_buf - read_n, packet_length - (uint32_t) read_n, buf + read_n, 0, 0 };
            if ((zstring = mysql_decode_big_data(&mbdi)))
            {
                read_n += mbdi.ext_header_len;
                packet_length += mbdi.ext_header_len + mbdi.ext_packet_len;
            }
            else
            {
                read_n = SW_AGAIN;
                goto _error;
            }
        }

        field = &client->response.columns[i];

        if (nul == 1)
        {
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "column#%d: name=%.*s, type=null", i, field->name_length, field->name);
            add_assoc_null(row_array, field->name);
            continue;
        }

        swTraceLog(SW_TRACE_MYSQL_CLIENT, "column#%d: name=%.*s, type=%d, value=%.*s, len=%lu", i, field->name_length, field->name, field->type, (int) len, buf + read_n, len);

        switch (field->type)
        {
        case SW_MYSQL_TYPE_NULL:
            add_assoc_null(row_array, field->name);
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
            if (unlikely(zstring))
            {
                zval _zdata, *zdata = &_zdata;
                ZVAL_STR(zdata, zstring);
                add_assoc_zval(row_array, field->name, zdata);
                zstring = NULL;
            }
            else
            {
                add_assoc_stringl(row_array, field->name, buf + read_n, len);
            }
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
                if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
                {
                    row.uint = strtoul(value_buffer, &error, 10);
                    if (*error != '\0')
                    {
                        read_n = -SW_MYSQL_ERR_CONVLONG;
                        goto _error;
                    }
                    add_assoc_long(row_array, field->name, row.uint);
                }
                else
                {
                    row.sint = strtol(value_buffer, &error, 10);
                    if (*error != '\0')
                    {
                        read_n = -SW_MYSQL_ERR_CONVLONG;
                        goto _error;
                    }
                    add_assoc_long(row_array, field->name, row.sint);
                }
            }
            else
            {
                add_assoc_stringl(row_array, field->name, buf + read_n, len);
            }
            break;
        case SW_MYSQL_TYPE_LONGLONG:
            if(client->connector.strict_type) {
                memcpy(value_buffer, buf + read_n, len);
                value_buffer[len] = 0;
                if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
                {
                    row.ubigint = strtoull(value_buffer, &error, 10);
                    if (*error != '\0') {
                        read_n = -SW_MYSQL_ERR_CONVLONGLONG;
                        goto _error;
                    }
                    if (unlikely(row.ubigint > ZEND_LONG_MAX))
                    {
                        goto _longlongstring;
                    }
                    add_assoc_long(row_array, field->name, row.ubigint);
                }
                else
                {
                    row.sbigint = strtoll(value_buffer, &error, 10);
                    if (*error != '\0') {
                        read_n = -SW_MYSQL_ERR_CONVLONGLONG;
                        goto _error;
                    }
                    add_assoc_long(row_array, field->name, row.sbigint);
                }
            }
            else
            {
                _longlongstring:
                add_assoc_stringl(row_array, field->name, buf + read_n, len);
            }
            break;
        case SW_MYSQL_TYPE_FLOAT:
            if(client->connector.strict_type) {
                memcpy(value_buffer, buf + read_n, len);
                value_buffer[len] = 0;
                row.mdouble = strtod(value_buffer, &error);
                if (*error != '\0') {
                    read_n = -SW_MYSQL_ERR_CONVFLOAT;
                    goto _error;
                }
                add_assoc_double(row_array, field->name, row.mdouble);
            }
            else
            {
                add_assoc_stringl(row_array, field->name, buf + read_n, len);
            }
            break;

        case SW_MYSQL_TYPE_DOUBLE:
            if(client->connector.strict_type) {
                memcpy(value_buffer, buf + read_n, len);
                value_buffer[len] = 0;
                row.mdouble = strtod(value_buffer, &error);
                if (*error != '\0') {
                    read_n = -SW_MYSQL_ERR_CONVDOUBLE;
                    goto _error;
                }
                add_assoc_double(row_array, field->name, row.mdouble);
            }
            else
            {
                add_assoc_stringl(row_array, field->name, buf + read_n, len);
            }
            break;

        default:
            swWarn("unknown field type[%d]", field->type);
            read_n = SW_ERR;
            _error:
            zval_ptr_dtor(row_array);
            efree(row_array);
            return read_n;
        }
        read_n += len;
    }

    add_next_index_zval(result_array, row_array);

    efree(row_array);

    return read_n;
}

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
        if (n > 4)
        {
            h = *(uint8_t *) (buf + 5);
            m = *(uint8_t *) (buf + 6);
            s = *(uint8_t *) (buf + 7);
        }
    }
    snprintf(result, DATETIME_MAX_SIZE, "%.4u-%.2u-%.2u %.2u:%.2u:%.2u", y, M, d, h, m, s);

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "n=%d", n);

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

    snprintf(result, DATETIME_MAX_SIZE, "%.2u:%.2u:%.2u", h, m, s);

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "n=%d", n);

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
    snprintf(result, DATETIME_MAX_SIZE, "%.4u-%.2u-%.2u", y, M, d);

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "n=%d", n);

    return n;
}

static void mysql_decode_year(char *buf, char *result)
{
    uint16_t y = *(uint16_t *) (buf);
    snprintf(result, DATETIME_MAX_SIZE, "%.4u", y);
}

static ssize_t mysql_decode_row_prepare(mysql_client *client, char *buf, uint32_t packet_length, size_t n_buf)
{
    uint32_t i;
    int tmp_len;
    ulong_t len = 0;
    char nul;
    ssize_t read_n = 0;

    unsigned int null_count = ((client->response.num_column + 9) / 8) + 1;
    buf += null_count;
    packet_length -= null_count;

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "null_count=%u", null_count);

    char datetime_buffer[DATETIME_MAX_SIZE];
    mysql_row row;

    zval *result_array = client->response.result_array;
    zval *row_array = sw_malloc_zval();
    array_init(row_array);

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "mysql_decode_row begin, num_column=%ld, packet_length=%u", client->response.num_column, packet_length);

    mysql_field *field = NULL;
    for (i = 0; i < client->response.num_column; i++)
    {
        field = &client->response.columns[i];
        /* to check Null-Bitmap @see https://dev.mysql.com/doc/internals/en/null-bitmap.html */
        if (((buf - null_count + 1)[((i + 2) / 8)] & (0x01 << ((i + 2) % 8))) != 0)
        {
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s is null", field->name);
            add_assoc_null(row_array, field->name);
            continue;
        }

        swTraceLog(SW_TRACE_MYSQL_CLIENT, "column#%d: name=%s, type=%d, size=%lu", i, field->name, field->type, field->length);

        switch (field->type)
        {
        /* Date Time */
        case SW_MYSQL_TYPE_TIME:
            len = mysql_decode_time(buf + read_n, datetime_buffer) + 1;
            add_assoc_stringl(row_array, field->name, datetime_buffer, 8);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%s", field->name, datetime_buffer);
            break;

        case SW_MYSQL_TYPE_YEAR:
            mysql_decode_year(buf + read_n, datetime_buffer);
            add_assoc_stringl(row_array, field->name, datetime_buffer, 4);
            len = 2;
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%s", field->name, datetime_buffer);
            break;

        case SW_MYSQL_TYPE_DATE:
            len = mysql_decode_date(buf + read_n, datetime_buffer) + 1;
            add_assoc_stringl(row_array, field->name, datetime_buffer, 10);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%s", field->name, datetime_buffer);
            break;

        case SW_MYSQL_TYPE_TIMESTAMP:
        case SW_MYSQL_TYPE_DATETIME:
            len = mysql_decode_datetime(buf + read_n, datetime_buffer) + 1;
            add_assoc_stringl(row_array, field->name, datetime_buffer, 19);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%s", field->name, datetime_buffer);
            break;

        case SW_MYSQL_TYPE_NULL:
            add_assoc_null(row_array, field->name);
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
            tmp_len = mysql_length_coded_binary(&buf[read_n], &len, &nul, packet_length - read_n);
            if (tmp_len == -1)
            {
                swWarn("mysql response parse error: bad lcb, tmp_len=%d", tmp_len);
                read_n = -SW_MYSQL_ERR_BAD_LCB;
                goto _error;
            }
            read_n += tmp_len;
            // WARNING: data may be longer than single packet (0x00fffff => 16M)
            if (unlikely(len > (uint32_t) (packet_length - read_n)))
            {
                zend_string *zstring;
                mysql_big_data_info mbdi = { len, n_buf - read_n, packet_length - (uint32_t) read_n, buf + read_n, 0, 0 };
                if ((zstring = mysql_decode_big_data(&mbdi)))
                {
                    zval _zdata, *zdata = &_zdata;
                    ZVAL_STR(zdata, zstring);
                    add_assoc_zval(row_array, field->name, zdata);
                    read_n += mbdi.ext_header_len;
                    packet_length += mbdi.ext_header_len + mbdi.ext_packet_len;
                }
                else
                {
                    read_n = SW_AGAIN;
                    goto _error;
                }
            }
            else
            {
                add_assoc_stringl(row_array, field->name, buf + read_n, len);
            }
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "len=%lu, %s=%.*s", len, field->name, (int) len, buf + read_n);
            break;

        /* Integer */
        case SW_MYSQL_TYPE_TINY:
            if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
            {
                row.utiny = *(uint8_t *) (buf + read_n);
                add_assoc_long(row_array, field->name, row.utiny);
                len = sizeof(row.utiny);
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%u", field->name, row.utiny);
            }
            else
            {
                row.stiny = *(int8_t *) (buf + read_n);
                add_assoc_long(row_array, field->name, row.stiny);
                len = sizeof(row.stiny);
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%d", field->name, row.stiny);
            }
            break;

        case SW_MYSQL_TYPE_SHORT:
            if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
            {
                row.small = *(uint16_t *) (buf + read_n);
                add_assoc_long(row_array, field->name, row.small);
                len = sizeof(row.small);
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%u", field->name, row.small);
            }
            else
            {
                row.ssmall = *(int16_t *) (buf + read_n);
                add_assoc_long(row_array, field->name, row.ssmall);
                len = sizeof(row.ssmall);
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%d", field->name, row.ssmall);
            }
            break;

        case SW_MYSQL_TYPE_INT24:
        case SW_MYSQL_TYPE_LONG:
            if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
            {
                row.uint = *(uint32_t *) (buf + read_n);
                add_assoc_long(row_array, field->name, row.uint);
                len = sizeof(row.uint);
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%u", field->name, row.uint);
            }
            else
            {
                row.sint = *(int32_t *) (buf + read_n);
                add_assoc_long(row_array, field->name, row.sint);
                len = sizeof(row.sint);
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%d", field->name, row.sint);
            }
            break;

        case SW_MYSQL_TYPE_LONGLONG:
            if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
            {
                row.ubigint = *(uint64_t *) (buf + read_n);
                add_assoc_ulong_safe(row_array, field->name, row.ubigint);
                len = sizeof(row.ubigint);
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%llu", field->name, row.ubigint);
            }
            else
            {
                row.sbigint = *(int64_t *) (buf + read_n);
                add_assoc_long(row_array, field->name, row.sbigint);
                len = sizeof(row.sbigint);
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%lld", field->name, row.sbigint);
            }
            break;

        case SW_MYSQL_TYPE_FLOAT:
            row.mfloat = *(float *) (buf + read_n);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%.7f", field->name, row.mfloat);
#if PHP_VERSION_ID >= 70011
            row.mdouble = _php_math_round(row.mfloat, 5, PHP_ROUND_HALF_DOWN);
#else
            row.mdouble = row.mfloat;
#endif
            add_assoc_double(row_array, field->name, row.mdouble);
            len = sizeof(row.mfloat);
            break;

        case SW_MYSQL_TYPE_DOUBLE:
            row.mdouble = *(double *) (buf + read_n);
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "%s=%.16f", field->name, row.mdouble);
            add_assoc_double(row_array, field->name, row.mdouble);
            len = sizeof(row.mdouble);
            break;

        default:
            swWarn("unknown field type[%d]", field->type);
            read_n = SW_ERR;
            _error:
            zval_ptr_dtor(row_array);
            efree(row_array);
            return read_n;
        }
        read_n += len;
    }

    add_next_index_zval(result_array, row_array);

    efree(row_array);

    return read_n + null_count;
}

static sw_inline int mysql_read_eof(mysql_client *client, char *buf, int n_buf)
{
    // not EOF packet
    if ((uint8_t) buf[4] != SW_MYSQL_PACKET_EOF || client->response.packet_length > SW_MYSQL_PACKET_EOF_MAX_SIZE)
    {
        return SW_ERR;
    }

    swMysqlPacketDump(buf, SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length, "EOF_Packet");

    // EOF_Packet = Packet header (4 bytes) + 0xFE + warning(2byte) + status(2byte)

    // skip packet header
    buf += SW_MYSQL_PACKET_HEADER_SIZE;

    // int<1>   header  [fe] EOF header
    buf += 1;

    // int<2>   warnings    number of warnings
    client->response.warnings = mysql_uint2korr(buf);
    buf += 2;

    // int<2>   status_flags    Status Flags
    client->response.status_code = mysql_uint2korr(buf);
    MYSQL_RESPONSE_BUFFER->offset += SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length;

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "EOF_Packet, warnings=%u, status_code=%u", client->response.warnings, client->response.status_code);

    return SW_OK;
}

static int mysql_query(zval *zobject, mysql_client *client, swString *sql, zval *callback)
{
    if (!client->cli)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed", client->fd);
        return SW_ERR;
    }
    if (!client->connected)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        swoole_php_error(E_WARNING, "mysql client is not connected to server");
        return SW_ERR;
    }
    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query");
        return SW_ERR;
    }

    if (client->buffer)
    {
        swString_clear(client->buffer);
    }

    if (callback != NULL)
    {
        Z_TRY_ADDREF_P(callback);
        client->callback = sw_zval_dup(callback);
    }

    client->cmd = SW_MYSQL_COM_QUERY;

    if (mysql_request_pack(sql, mysql_request_buffer) < 0)
    {
        return SW_ERR;
    }
    //send query
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_update_property_bool(swoole_mysql_coro_ce, zobject, ZEND_STRL("connected"), 0);
            zend_update_property_long(swoole_mysql_coro_ce, zobject, ZEND_STRL("errno"), 2013);
            zend_update_property_string(swoole_mysql_coro_ce, zobject, ZEND_STRL("error"), "Lost connection to MySQL server during query");
        }
        return SW_ERR;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        return SW_OK;
    }
}

static void mysql_columns_free(mysql_client *client)
{
    if (client->response.columns)
    {
        uint32_t i;
        for (i = 0; i < client->response.num_column; i++)
        {
            if (client->response.columns[i].buffer)
            {
                efree(client->response.columns[i].buffer);
                client->response.columns[i].buffer = NULL;
            }
        }
        efree(client->response.columns);
        client->response.columns = NULL;
    }
}

static int mysql_parse_prepare_result(mysql_client *client, char *buf, size_t n_buf)
{
    // not COM_STMT_PREPARE_OK packet
    if ((uint8_t) buf[4] != SW_MYSQL_PACKET_OK || client->cmd != SW_MYSQL_COM_STMT_PREPARE || client->response.packet_length < 12)
    {
        return SW_ERR;
    }

    swMysqlPacketDump(buf, SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length, "COM_STMT_PREPARE_OK_Packet");

    // skip the packet header
    buf += SW_MYSQL_PACKET_HEADER_SIZE;

    mysql_statement *stmt = (mysql_statement *) emalloc(sizeof(mysql_statement));
    // status (1) -- [00] OK
    buf += 1;

    // statement_id (4) -- statement-id
    stmt->id = mysql_uint4korr(buf);
    buf += 4;

    // num_columns (2) -- number of columns
    stmt->field_count = mysql_uint2korr(buf);
    buf += 2;

    // num_params (2) -- number of params
    stmt->unreaded_param_count = stmt->param_count = mysql_uint2korr(buf);
    buf += 2;

    // reserved_1 (1) -- [00] filler
    buf += 1;

    // warning_count (2) -- number of warnings
    stmt->warning_count = mysql_uint2korr(buf);
    stmt->result = NULL;
    stmt->buffer = NULL;
    client->statement = stmt;
    stmt->client = client;

    MYSQL_RESPONSE_BUFFER->offset += SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length;

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "stmt_id=%u, field_count=%u, param_count=%u, warning_count=%u", stmt->id,
            stmt->field_count, stmt->param_count, stmt->warning_count);

    return SW_OK;
}

static int mysql_decode_field(char *buf, size_t len, mysql_field *col)
{
    uint32_t i;
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
    swString *buffer = MYSQL_RESPONSE_BUFFER;
    char *p = buffer->str + buffer->offset;
    size_t n_buf = buffer->length - buffer->offset;
    int ret;

    for (; client->response.index_column < client->response.num_column; client->response.index_column++)
    {
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "index_index_column=%ld, n_buf=%zu", client->response.index_column, (uintmax_t) n_buf);

        // Ensure that we've received the complete packet
        if (mysql_ensure_packet(p, n_buf) == SW_ERR)
        {
            return SW_AGAIN;
        }

        client->response.packet_length = mysql_uint3korr(p);
        client->response.packet_number = p[3];

        swMysqlPacketDump(p, SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length, "Protocol::ColumnDefinition");

        // skip the packet header
        p += SW_MYSQL_PACKET_HEADER_SIZE;
        n_buf -= SW_MYSQL_PACKET_HEADER_SIZE;

        ret = mysql_decode_field(p, client->response.packet_length, &client->response.columns[client->response.index_column]);
        if (ret > 0)
        {
            p += client->response.packet_length;
            n_buf -= client->response.packet_length;
            buffer->offset += (SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length);
        }
        else
        {
            swWarn("mysql_decode_field failed, code=%d", ret);
            return ret < 0 ? ret : SW_ERR;
        }
    }

    // Ensure that we've received the complete EOF_Packet
    if (mysql_ensure_packet(p, n_buf) == SW_ERR)
    {
        return SW_AGAIN;
    }

    client->response.packet_length = mysql_uint3korr(p);
    client->response.packet_number = p[3];

    if (mysql_read_eof(client, p, n_buf) != SW_OK)
    {
        swWarn("unexpected mysql non-eof packet");
        return SW_ERR;
    }

    if (client->cmd != SW_MYSQL_COM_STMT_PREPARE)
    {
        if (!client->response.result_array)
        {
            client->response.result_array = sw_malloc_zval();;
            array_init(client->response.result_array);
        }
    }

    p += SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length;
    n_buf -= SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length;
    buffer->offset += p - (buffer->str + buffer->offset);

    return SW_OK;
}

static sw_inline int mysql_read_params(mysql_client *client)
{
    while (1)
    {
        swString *buffer = MYSQL_RESPONSE_BUFFER;
        char *p = buffer->str + buffer->offset;
        size_t n_buf = buffer->length - buffer->offset;

        swTraceLog(SW_TRACE_MYSQL_CLIENT, "n_buf=%zu, length=%u", (uintmax_t) n_buf, client->response.packet_length);

        // Ensure that we've received the complete packet
        if (mysql_ensure_packet(p, n_buf) == SW_ERR)
        {
            return SW_AGAIN;
        }

        client->response.packet_length = mysql_uint3korr(p);
        client->response.packet_number = p[3];

        if (client->statement->unreaded_param_count > 0)
        {
            // Read and ignore parameter field. Sentence from MySQL source:
            // skip parameters data: we don't support it yet
            buffer->offset += (SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length);
            client->statement->unreaded_param_count--;

            swMysqlPacketDump(p, SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length, "Protocol::ParameterDefinition");

            swTraceLog(SW_TRACE_MYSQL_CLIENT, "read param, count=%d", client->statement->unreaded_param_count);

            continue;
        }
        else
        {
            return mysql_read_eof(client, p, n_buf);
        }
    }
}


/**
 * @var char*    p      => packet beginning point
 * @var size_t   n_buf  => remaining buffer length
 * @var ssize_t  read_n => already read buffer len
 */
static sw_inline int mysql_read_rows(mysql_client *client)
{
    swString *buffer = MYSQL_RESPONSE_BUFFER;
    char *p = buffer->str + buffer->offset;
    size_t n_buf = buffer->length - buffer->offset;
    ssize_t read_n = 0;

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "n_buf=%ju", (uintmax_t) n_buf);

    //RecordSet parse
    while (n_buf > 0)
    {
        // Ensure that we've received the complete packet
        if (mysql_ensure_packet(p, n_buf) == SW_ERR)
        {
            return SW_AGAIN;
        }

        client->response.packet_length = mysql_uint3korr(p);
        client->response.packet_number = p[3];

        //RecordSet end
        if (mysql_read_eof(client, p, n_buf) == SW_OK)
        {
            mysql_columns_free(client);
            return SW_OK;
        }
        // ERR Instead of EOF
        // @see: https://dev.mysql.com/doc/internals/en/err-instead-of-eof.html
        else if (mysql_read_err(client, p, n_buf) == SW_OK)
        {
            mysql_columns_free(client);
            return SW_OK;
        }

        swTraceLog(SW_TRACE_MYSQL_CLIENT, "record size=%d", client->response.packet_length);

        // ProtocolBinary::ResultSetRow
        swMysqlPacketDump(p, SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length , "ProtocolBinary::ResultSetRow");


        if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
        {
            // for execute
            read_n = mysql_decode_row_prepare(
                client,
                p + SW_MYSQL_PACKET_HEADER_SIZE,
                client->response.packet_length,
                n_buf - SW_MYSQL_PACKET_HEADER_SIZE
            );
        }
        else
        {
            // for query
            read_n = mysql_decode_row(
                client,
                p + SW_MYSQL_PACKET_HEADER_SIZE,
                client->response.packet_length,
                n_buf - SW_MYSQL_PACKET_HEADER_SIZE
            );
        }

        if (unlikely(read_n < 0))
        {
            // TODO: handle all decode error here
            if (read_n == SW_AGAIN)
            {
                return SW_AGAIN;
            }
            mysql_columns_free(client);
            return read_n;
        }

        // next row
        p += SW_MYSQL_PACKET_HEADER_SIZE + read_n;
        n_buf -= SW_MYSQL_PACKET_HEADER_SIZE + read_n;
        buffer->offset += SW_MYSQL_PACKET_HEADER_SIZE + read_n;
        client->response.num_row++;
    }

    // missing eof or err packet
    return SW_AGAIN;
}

// this function is used to check if multi responses has received over.
static int mysql_is_over(mysql_client *client)
{
    swString *buffer = MYSQL_RESPONSE_BUFFER;
    char *p;
    off_t remaining_size, temp_remaining_len = 0;
    uint32_t packet_length;
    ulong_t val = 0;

    if (buffer->length < client->want_length)
    {
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "want=%ju, but only=%ju", (uintmax_t) client->want_length, (uintmax_t) buffer->length);
        return SW_AGAIN;
    }
    remaining_size = buffer->length - client->check_offset; // remaining buffer size
    while (remaining_size > 0) // if false: have already check all of the data
    {
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "check packet from %jd, remaining=%jd", (intmax_t) client->check_offset, (intmax_t) remaining_size);
        p = buffer->str + client->check_offset; // where to start checking now
        if (unlikely(buffer->length < (size_t) client->check_offset + SW_MYSQL_PACKET_HEADER_SIZE))
        {
            client->want_length = client->check_offset + SW_MYSQL_PACKET_HEADER_SIZE;
            break; // header incomplete
        }
        packet_length = mysql_uint3korr(p); // parse packet length
        // add header
        p += SW_MYSQL_PACKET_HEADER_SIZE;
        remaining_size -= SW_MYSQL_PACKET_HEADER_SIZE;
        if (remaining_size < packet_length) // packet is incomplete
        {
            client->want_length = client->check_offset + SW_MYSQL_PACKET_HEADER_SIZE + packet_length;
            break;
        }

        client->check_offset += (SW_MYSQL_PACKET_HEADER_SIZE + packet_length); // add header length + packet length
        if ((size_t) client->check_offset >= buffer->length) // if false: more packets exist, skip the current one
        {
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "check the last packet, length=%u", packet_length);
            switch ((uint8_t) p[0])
            {
            case SW_MYSQL_PACKET_EOF: // eof
            {
                // +type +warning
                p += 3;
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "meet eof packet and flag=%d", mysql_uint2korr(p));
                goto _check_flag;
            }
            case SW_MYSQL_PACKET_OK: // ok
            {
                val = 0;
                char nul;
                int retcode;
                temp_remaining_len = remaining_size;

                // +type
                p++;
                temp_remaining_len--;

                retcode = mysql_length_coded_binary(p, &val, &nul, temp_remaining_len); // affect rows
                p += retcode;
                temp_remaining_len -= retcode;

                retcode = mysql_length_coded_binary(p, &val, &nul, temp_remaining_len); // insert id
                p += retcode;
                temp_remaining_len -= retcode;

                swTraceLog(SW_TRACE_MYSQL_CLIENT, "meet ok packet");
                _check_flag:
                if ((mysql_uint2korr(p) & SW_MYSQL_SERVER_MORE_RESULTS_EXISTS) == 0)
                {
                    _over:
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "packet over on=%jd", (intmax_t) client->check_offset);
                    client->want_length = 0;
                    client->check_offset = 0;
                    return SW_OK;
                }
                break;
            }
            case SW_MYSQL_PACKET_ERR: // response type = error
            {
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "meet error packet");
                goto _over;
            }
            }
        }

        // not complete and without remaining data
        remaining_size -= packet_length;
        if (remaining_size <= 0)
        {
            break; // again
        }
    }

    return SW_AGAIN;
}

static int mysql_response(mysql_client *client)
{
    swString *buffer = MYSQL_RESPONSE_BUFFER;

    char *p;
    int ret;
    char nul;
    size_t n_buf;

    while ((n_buf = buffer->length - buffer->offset) > 0)
    {
        p = buffer->str + buffer->offset;
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "client->state=%d, n_buf=%zu", client->state, n_buf);

        switch (client->state)
        {
        case SW_MYSQL_STATE_READ_START:
            // Ensure that we've received the complete packet
            if (mysql_ensure_packet(p, n_buf) == SW_ERR)
            {
                return SW_AGAIN;
            }

            client->response.packet_length = mysql_uint3korr(p);
            client->response.packet_number = p[3];
            client->response.response_type = p[4];

            /* error */
            if (mysql_read_err(client, p, n_buf) == SW_OK)
            {
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* eof */
            else if (mysql_read_eof(client, p, n_buf) == SW_OK)
            {
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* ok */
            else if (mysql_read_ok(client, p, n_buf) == SW_OK)
            {
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* COM_STMT_PREPARE_OK */
            else if (mysql_parse_prepare_result(client, p, n_buf) == SW_OK)
            {
                client->response.num_column = client->statement->field_count;
                if (client->response.num_column > 0)
                {
                    client->response.columns = (mysql_field *) ecalloc(client->response.num_column, sizeof(mysql_field));
                }
                if (client->statement->param_count > 0)
                {
                    client->state = SW_MYSQL_STATE_READ_PARAM;
                }
                else if (client->statement->field_count > 0)
                {
                    client->state = SW_MYSQL_STATE_READ_FIELD;
                }
                else
                {
                    return SW_OK;
                }
                break;
            }
            /* result set */
            else
            {
                swMysqlPacketDump(p, SW_MYSQL_PACKET_HEADER_SIZE + client->response.packet_length, "ResultSet");

                //Protocol::LengthEncodedInteger
                ret = mysql_length_coded_binary(p + SW_MYSQL_PACKET_HEADER_SIZE, &client->response.num_column, &nul, n_buf - SW_MYSQL_PACKET_HEADER_SIZE);
                if (ret < 0)
                {
                    return SW_ERR;
                }
                buffer->offset += (SW_MYSQL_PACKET_HEADER_SIZE + ret);

                swTraceLog(SW_TRACE_MYSQL_CLIENT, "ResultSet_Packet: num_of_fields=%lu", client->response.num_column);

                // easy to the safe side: but under what circumstances would num_column will be 0 in result set?
                if (client->response.num_column > 0)
                {
                    client->response.columns = (mysql_field *) ecalloc(client->response.num_column, sizeof(mysql_field));
                }

                client->state = SW_MYSQL_STATE_READ_FIELD;
                break;
            }

        /* data of fields */
        case SW_MYSQL_STATE_READ_FIELD:
            if ((ret = mysql_read_columns(client)) < 0)
            {
                return ret;
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

        /* data of rows */
        case SW_MYSQL_STATE_READ_ROW:
            if ((ret = mysql_read_rows(client)) < 0)
            {
                return ret;
            }
            else
            {
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }

        /* prepare statment params */
        case SW_MYSQL_STATE_READ_PARAM:
            if ((ret = mysql_read_params(client)) < 0)
            {
                return ret;
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

    return SW_AGAIN;
}


int mysql_request_pack(swString *sql, swString *buffer)
{
    swString_clear(buffer);
    bzero(buffer->str, 5);
    //length
    mysql_pack_length(sql->length + 1, buffer->str);
    //command
    buffer->str[4] = SW_MYSQL_COM_QUERY;
    buffer->length = 5;
    return swString_append(buffer, sql);
}

int mysql_prepare_pack(swString *sql, swString *buffer)
{
    swString_clear(buffer);
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

int mysql_get_result(mysql_connector *connector, char *buf, size_t len)
{
    char *tmp = buf;
    uint32_t packet_length = mysql_uint3korr(tmp);
    if (len < SW_MYSQL_PACKET_HEADER_SIZE + packet_length)
    {
        return 0;
    }
    //int packet_number = tmp[3];
    tmp += SW_MYSQL_PACKET_HEADER_SIZE;

    uint8_t opcode = *tmp;
    tmp += 1;

    //ERROR Packet
    if (opcode == SW_MYSQL_PACKET_ERR)
    {
        swMysqlPacketDump(tmp - 5, SW_MYSQL_PACKET_HEADER_SIZE + packet_length, "Handshake ERR_Packet");
        connector->error_code = *(uint16_t *) tmp;
        connector->error_msg = tmp + 2;
        connector->error_length = packet_length - 3;
        return -1;
    }
    else
    {
        swMysqlPacketDump(tmp - 5, SW_MYSQL_PACKET_HEADER_SIZE + packet_length, "Handshake OK_Packet");
        return 1;
    }
}

static void php_swoole_sha256(const char *str, int _len, unsigned char *digest)
{
    PHP_SHA256_CTX context;
    PHP_SHA256Init(&context);
    PHP_SHA256Update(&context, (unsigned char *) str, _len);
    PHP_SHA256Final(digest, &context);
}

//sha256
static void mysql_sha2_password_with_nonce(char* ret, char* nonce, char* password, size_t password_len)
{
    // XOR(SHA256(password), SHA256(SHA256(SHA256(password)), nonce))
    char hashed[32], double_hashed[32];
    php_swoole_sha256(password, password_len, (unsigned char *) hashed);
    php_swoole_sha256(hashed, 32, (unsigned char *) double_hashed);
    char combined[32 + SW_MYSQL_NONCE_LENGTH]; //double-hashed + nonce
    memcpy(combined, double_hashed, 32);
    memcpy(combined + 32, nonce, SW_MYSQL_NONCE_LENGTH);
    char xor_bytes[32];
    php_swoole_sha256(combined, 32 + SW_MYSQL_NONCE_LENGTH, (unsigned char *) xor_bytes);
    int i;
    for (i = 0; i < 32; i++)
    {
        hashed[i] ^= xor_bytes[i];
    }
    memcpy(ret, hashed, 32);
}

/**
 * Return: password length
 */
static int mysql_auth_encrypt_dispatch(char *buf, char *auth_plugin_name, char *password, size_t password_len, char* nonce, int *next_state)
{
    if (!auth_plugin_name || strcasecmp("mysql_native_password", auth_plugin_name) == 0)
    {
        // mysql_native_password is default
        // auth-response
        char hash_0[20];
        bzero(hash_0, sizeof (hash_0));
        php_swoole_sha1(password, password_len, (uchar *) hash_0);

        char hash_1[20];
        bzero(hash_1, sizeof (hash_1));
        php_swoole_sha1(hash_0, sizeof (hash_0), (uchar *) hash_1);

        char str[40];
        memcpy(str, nonce, 20);
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

        memcpy(buf, hash_3, 20);

        return 20;
    }
    else if (strcasecmp("caching_sha2_password", auth_plugin_name) == 0)
    {
        char hashed[32];
        mysql_sha2_password_with_nonce(
                (char *) hashed,
                (char *) nonce,
                password,
                password_len
        );

        // copy hashed data to connector buf
        memcpy(buf, (char *) hashed, 32);
        *next_state = SW_MYSQL_HANDSHAKE_WAIT_SIGNATURE;

        return 32;
    }
    else
    {
        // unknown
        swWarn("Unknown auth plugin: %s", auth_plugin_name);

        return 0;
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
int mysql_handshake(mysql_connector *connector, char *buf, size_t len)
{
    char *tmp = buf;
    int next_state = SW_MYSQL_HANDSHAKE_WAIT_RESULT; // ret is the next handshake state

    /**
     * handshake request
     */
    mysql_handshake_request request;
    bzero(&request, sizeof(request));

    request.packet_length = mysql_uint3korr(tmp);
    //continue to wait for data
    if (len < (uint32_t) (SW_MYSQL_PACKET_HEADER_SIZE + request.packet_length))
    {
        return 0;
    }

    swMysqlPacketDump(tmp, SW_MYSQL_PACKET_HEADER_SIZE + request.packet_length, "Protocol::HandshakeV10");

    request.packet_number = tmp[3];
    tmp += SW_MYSQL_PACKET_HEADER_SIZE;

    request.protocol_version = *tmp;
    tmp += 1;

    //ERROR Packet
    if (request.protocol_version == SW_MYSQL_PACKET_ERR)
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
#ifdef SW_MYSQL_RSA_SUPPORT
            memcpy(connector->auth_plugin_data, request.auth_plugin_data, SW_MYSQL_NONCE_LENGTH);
#endif
            tmp += len;
        }

        if (request.capability_flags & SW_MYSQL_CLIENT_PLUGIN_AUTH)
        {
            request.auth_plugin_name = tmp;
            request.l_auth_plugin_name = MIN(strlen(tmp), len - (tmp - buf));
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "use %s auth plugin", request.auth_plugin_name);
        }
    }

    int value;
    tmp = connector->buf + 4;

    //capability flags, CLIENT_PROTOCOL_41 always set
    value = SW_MYSQL_CLIENT_LONG_PASSWORD | SW_MYSQL_CLIENT_PROTOCOL_41 | SW_MYSQL_CLIENT_SECURE_CONNECTION
            | SW_MYSQL_CLIENT_CONNECT_WITH_DB | SW_MYSQL_CLIENT_PLUGIN_AUTH | SW_MYSQL_CLIENT_MULTI_RESULTS;
    memcpy(tmp, &value, sizeof(value));
    tmp += 4;

    swTraceLog(SW_TRACE_MYSQL_CLIENT, "Server protocol=%d, version=%s, capabilites=0x%08x, status=%u, Client capabilites=0x%08x",
        request.protocol_version, request.server_version, request.capability_flags, request.status_flags, value);

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
        int length = 0;
        length = mysql_auth_encrypt_dispatch(
                tmp + 1,
                request.auth_plugin_name,
                connector->password,
                connector->password_len,
                request.auth_plugin_data,
                &next_state
        );
        *tmp = length;
        tmp += length + 1;
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

    swMysqlPacketDump(connector->buf, SW_MYSQL_PACKET_HEADER_SIZE + connector->packet_length, "Protocol::HandshakeResponse41");

    return next_state;
}

// we may need it one day but now
// we can reply the every auth plugin requirement on the first handshake
int mysql_auth_switch(mysql_connector *connector, char *buf, size_t len)
{
    char *tmp = buf;
    if ((uint8_t) tmp[4] != SW_MYSQL_PACKET_EOF)
    {
        // out of the order packet
        return SW_ERR;
    }

    int next_state = SW_MYSQL_HANDSHAKE_WAIT_RESULT;

    uint32_t packet_length = mysql_uint3korr(tmp);
    //continue to wait for data
    if (len < SW_MYSQL_PACKET_HEADER_SIZE + packet_length)
    {
        return SW_AGAIN;
    }
    int packet_number = tmp[3];
    tmp += SW_MYSQL_PACKET_HEADER_SIZE;

    // type
    tmp += 1;

    // clear
    connector->packet_length = 0;
    memset(connector->buf, 0, 512);

    // string[NUL]    plugin name
    char auth_plugin_name[32];
    int auth_plugin_name_len = 0;
    uint32_t i;
    for (i = 0; i < packet_length; i++)
    {
        auth_plugin_name[auth_plugin_name_len] = tmp[auth_plugin_name_len];
        auth_plugin_name_len++;
        if (tmp[auth_plugin_name_len] == 0x00)
        {
            break;
        }
    }
    auth_plugin_name[auth_plugin_name_len] = '\0';
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "auth switch plugin name=%s", auth_plugin_name);
    tmp += auth_plugin_name_len + 1; // name + 0x00

    // if auth switch is triggered, password can't be empty
    // string    auth plugin data
    char auth_plugin_data[20];
    memcpy((char *)auth_plugin_data, tmp, 20);

    // create auth switch response packet
    connector->packet_length += mysql_auth_encrypt_dispatch(
            (char *) (connector->buf + 4),
            auth_plugin_name,
            connector->password,
            connector->password_len,
            auth_plugin_data,
            &next_state
    );
    // 3 for packet length
    mysql_pack_length(connector->packet_length, connector->buf);
    // 1 packet num
    connector->buf[3] = packet_number + 1;

    return next_state;
}

int mysql_parse_auth_signature(swString *buffer, mysql_connector *connector)
{
    char *tmp = buffer->str;
    uint32_t packet_length = mysql_uint3korr(tmp);
    //continue to wait for data
    if (buffer->length < SW_MYSQL_PACKET_HEADER_SIZE + packet_length)
    {
        return SW_AGAIN;
    }

    swMysqlPacketDump(tmp, SW_MYSQL_PACKET_HEADER_SIZE + packet_length, "Auth");

    int packet_number = tmp[3];
    tmp += SW_MYSQL_PACKET_HEADER_SIZE;

    // signature
    if ((uint8_t) tmp[0] != SW_MYSQL_AUTH_SIGNATURE)
    {
        return SW_MYSQL_AUTH_SIGNATURE_ERROR;
    }

    // remaining length
    buffer->offset = SW_MYSQL_PACKET_HEADER_SIZE + packet_length;
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "before signature remaining=%ju", (uintmax_t) (buffer->length - buffer->offset));

    if ((uint8_t)tmp[1] == SW_MYSQL_AUTH_SIGNATURE_FULL_AUTH_REQUIRED)
    {
        // create RSA prepared response
        connector->packet_length = 1;
        memset(connector->buf, 0, 512);
        // 3 for packet length
        mysql_pack_length(connector->packet_length, connector->buf);
        // 1 packet number
        connector->buf[3] = packet_number + 1;
        // as I am OK
        connector->buf[4] = SW_MYSQL_AUTH_SIGNATURE_RSA_PREPARED;
    }

    // signature value
    return tmp[1];
}

#ifdef SW_MYSQL_RSA_SUPPORT
//  Caching sha2 authentication. Public key request and send encrypted password
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchResponse
int mysql_parse_rsa(mysql_connector *connector, char *buf, size_t len)
{
    // clear
    connector->packet_length = 0;
    memset(connector->buf, 0, 512);

    char *tmp = buf;

    uint32_t packet_length = mysql_uint3korr(tmp);
    //continue to wait for data
    if (len < SW_MYSQL_PACKET_HEADER_SIZE + packet_length)
    {
        return SW_AGAIN;
    }
    int packet_number = tmp[3];
    tmp += SW_MYSQL_PACKET_HEADER_SIZE;

    int rsa_public_key_length = packet_length;
    while (tmp[0] != 0x2d)
    {
        tmp++; // ltrim
        rsa_public_key_length--;
    }
    char rsa_public_key[rsa_public_key_length + 1]; //rsa + '\0'
    memcpy((char *)rsa_public_key, tmp, rsa_public_key_length);
    rsa_public_key[rsa_public_key_length] = '\0';
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "rsa-length=%d;\nrsa-key=[%.*s]", rsa_public_key_length, rsa_public_key_length, rsa_public_key);

    int password_len = connector->password_len + 1;
    unsigned char password[password_len];
    // copy to stack
    memcpy((char *)password, connector->password, password_len);
    // add NUL terminator to password
    password[password_len - 1] = '\0';
    // XOR the password bytes with the challenge
    int i;
    for (i = 0; i < password_len; i++)
    {
        password[i] ^= connector->auth_plugin_data[i % SW_MYSQL_NONCE_LENGTH];
    }

    // prepare RSA public key
    BIO *bio = NULL;
    RSA *public_rsa = NULL;
    if (unlikely((bio = BIO_new_mem_buf((void *)rsa_public_key, -1)) == NULL))
    {
        swWarn("BIO_new_mem_buf publicKey error!");
        return SW_ERR;
    }
    // PEM_read_bio_RSA_PUBKEY
    ERR_clear_error();
    if (unlikely((public_rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL)) == NULL))
    {
        ERR_load_crypto_strings();
        char err_buf[512];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        swWarn("[PEM_read_bio_RSA_PUBKEY ERROR]: %s", err_buf);

        return SW_ERR;
    }
    BIO_free_all(bio);
    // encrypt with RSA public key
    int rsa_len = RSA_size(public_rsa);
    unsigned char encrypt_msg[rsa_len];
    // RSA_public_encrypt
    ERR_clear_error();
    int flen = rsa_len - 42;
    flen = password_len > flen ? flen : password_len;
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "rsa_len=%d", rsa_len);
    if (unlikely(RSA_public_encrypt(flen, (const unsigned char *)password, (unsigned char *)encrypt_msg, public_rsa, RSA_PKCS1_OAEP_PADDING) < 0))
    {
        ERR_load_crypto_strings();
        char err_buf[512];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        swWarn("[RSA_public_encrypt ERROR]: %s", err_buf);
        return SW_ERR;
    }
    RSA_free(public_rsa);

    memcpy((char *)connector->buf + 4, (char *)encrypt_msg, rsa_len); // copy rsa to buf
    connector->packet_length = rsa_len;

    // 3 for packet length
    mysql_pack_length(connector->packet_length, connector->buf);
    // 1 packet number
    connector->buf[3] = packet_number + 1;

    return SW_OK;
}
#endif

static int swoole_mysql_coro_execute(zval *zobject, mysql_client *client, zval *params)
{

    PHPCoroutine::check_bind("mysql client", client->cid);

    if (!client->cli || client->state == SW_MYSQL_STATE_CLOSED)
    {
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed", client->fd);
        return SW_ERR;
    }

    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query");
        return SW_ERR;
    }

    mysql_statement *statement = (mysql_statement *) swoole_get_object(zobject);
    if (!statement)
    {
        swoole_php_fatal_error(E_WARNING, "mysql preparation is not ready");
        return SW_ERR;
    }

    long lval;
    char buf[10];
    zval *value;

    uint16_t param_count = 0;
    if (params)
    {
        param_count = php_swoole_array_length(params);
    }

    if (param_count != statement->param_count)
    {
        swoole_php_fatal_error(E_WARNING, "mysql statement#%u expects %u parameter, %u given", statement->id, statement->param_count, param_count);
        return SW_ERR;
    }

    swString_clear(mysql_request_buffer);

    client->cmd = SW_MYSQL_COM_STMT_EXECUTE;
    client->statement = statement;

    bzero(mysql_request_buffer->str, 5);
    //command
    mysql_request_buffer->str[4] = SW_MYSQL_COM_STMT_EXECUTE;
    mysql_request_buffer->length = 5;
    char *p = mysql_request_buffer->str;
    p += 5;

    // stmt.id
    mysql_int4store(p, statement->id);
    p += 4;
    // flags = CURSOR_TYPE_NO_CURSOR
    mysql_int1store(p, 0);
    p += 1;
    // iteration_count
    mysql_int4store(p, 1);
    p += 4;

    mysql_request_buffer->length += 9;

    if (param_count != 0)
    {
       //null bitmap
       size_t null_start_offset = p - mysql_request_buffer->str;
       unsigned int map_size = (param_count + 7) / 8;
       memset(p, 0, map_size);
       p += map_size;
       mysql_request_buffer->length += map_size;

       //rebind
       mysql_int1store(p, 1);
       p += 1;
       mysql_request_buffer->length += 1;

       size_t type_start_offset = p - mysql_request_buffer->str;
       p += param_count * 2;
       mysql_request_buffer->length += param_count * 2;

       zend_ulong index = 0;
       ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(params), value)
       {
            if (ZVAL_IS_NULL(value))
            {
                *((mysql_request_buffer->str + null_start_offset) + (index / 8)) |= (1UL << (index % 8));
                mysql_int2store((mysql_request_buffer->str + type_start_offset) + (index * 2), SW_MYSQL_TYPE_NULL);
            }
            else
            {
                mysql_int2store((mysql_request_buffer->str + type_start_offset) + (index * 2), SW_MYSQL_TYPE_VAR_STRING);
                zend::string str_value(value);

                if (str_value.len() > 0xffff)
                {
                    buf[0] = (char) SW_MYSQL_TYPE_VAR_STRING;
                    if (swString_append_ptr(mysql_request_buffer, buf, 1) < 0)
                    {
                        return SW_ERR;
                    }
                }
                else if (str_value.len() > 250)
                {
                    buf[0] = (char) SW_MYSQL_TYPE_BLOB;
                    if (swString_append_ptr(mysql_request_buffer, buf, 1) < 0)
                    {
                        return SW_ERR;
                    }
                }
                lval = mysql_write_lcb(buf, str_value.len());
                if (swString_append_ptr(mysql_request_buffer, buf, lval) < 0)
                {
                    return SW_ERR;
                }
                if (swString_append_ptr(mysql_request_buffer, str_value.val(), str_value.len()) < 0)
                {
                    return SW_ERR;
                }
            }
            index++;
       }
       ZEND_HASH_FOREACH_END();
    }

    //length
    mysql_pack_length(mysql_request_buffer->length - 4, mysql_request_buffer->str);

    //send data
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_update_property_bool(swoole_mysql_coro_ce, zobject, ZEND_STRL("connected"), 0);
            zend_update_property_long(swoole_mysql_coro_ce, zobject, ZEND_STRL("errno"), 2013);
            zend_update_property_string(swoole_mysql_coro_ce, zobject, ZEND_STRL("error"), "Lost connection to MySQL server during query");
        }
        return SW_ERR;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        return SW_OK;
    }
}

static int swoole_mysql_coro_parse_response(mysql_client *client, zval **result, int from_next_result)
{
    zval *zobject = client->object;
    int ret = mysql_response(client);

    if (ret < 0)
    {
        if (ret == SW_AGAIN)
        {
            return SW_AGAIN;
        }
        else // handler error
        {
            static const char* errmsg = "mysql response packet parse error";
            client->response.response_type = SW_MYSQL_PACKET_ERR;
            client->response.error_code = ret;
            client->response.server_msg = (char *) errmsg;
            client->response.l_server_msg = strlen(errmsg);
            if (client->response.result_array)
            {
                sw_zval_free(client->response.result_array);
                client->response.result_array = nullptr;
            }
            if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
            {
                if (client->statement && client->statement->result)
                {
                    sw_zval_free(client->statement->result);
                    client->statement->result = NULL;
                }
            }
        }
    }

    //remove from eventloop
    //reactor->del(reactor, event->fd);

    zend_update_property_long(
        swoole_mysql_coro_ce, zobject,
        ZEND_STRL("affected_rows"), client->response.affected_rows
    );
    zend_update_property_long(
        swoole_mysql_coro_ce, zobject,
        ZEND_STRL("insert_id"), client->response.insert_id
    );

    if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
    {
        zend_update_property_long(
            swoole_mysql_coro_statement_ce, client->statement->object,
            ZEND_STRL("affected_rows"), client->response.affected_rows
        );
        zend_update_property_long(
            swoole_mysql_coro_statement_ce, client->statement->object,
            ZEND_STRL("insert_id"), client->response.insert_id
        );
    }

    client->state = SW_MYSQL_STATE_QUERY;

    // OK
    if (client->response.response_type == SW_MYSQL_PACKET_OK)
    {
        *result = sw_malloc_zval();
        // prepare finished and create statement
        if (client->cmd == SW_MYSQL_COM_STMT_PREPARE)
        {
            if (client->statement_list == NULL)
            {
                client->statement_list = swLinkedList_new(0, NULL);
            }
            swLinkedList_append(client->statement_list, client->statement);
            object_init_ex(*result, swoole_mysql_coro_statement_ce);
            swoole_set_object(*result, client->statement);
            client->statement->object = sw_zval_dup(*result);
        }
        else
        {
            if (from_next_result)
            {
                // pass the ok response ret val
                ZVAL_NULL(*result);
            }
            else
            {
                ZVAL_TRUE(*result);
            }
        }
    }
    // ERROR
    else if (client->response.response_type == SW_MYSQL_PACKET_ERR)
    {
        *result = sw_malloc_zval();
        ZVAL_FALSE(*result);

        zend_update_property_stringl(
            swoole_mysql_coro_ce, zobject, ZEND_STRL("error"),
            client->response.server_msg, client->response.l_server_msg
        );
        zend_update_property_long(
            swoole_mysql_coro_ce, zobject, ZEND_STRL("errno"),
            client->response.error_code
        );

        if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
        {
            zend_update_property_stringl(
                swoole_mysql_coro_statement_ce, client->statement->object,
                ZEND_STRL("error"), client->response.server_msg, client->response.l_server_msg
            );
            zend_update_property_long(
                swoole_mysql_coro_statement_ce, client->statement->object,
                ZEND_STRL("errno"), client->response.error_code
            );
        }
    }
    // ResultSet
    else
    {
        if (client->connector.fetch_mode && client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
        {
            if (client->statement->result)
            {
                // free the last one
                sw_zval_free(client->statement->result);
                client->statement->result = NULL;
            }
            // save result on statement and wait for fetch
            client->statement->result = client->response.result_array;
            client->response.result_array = NULL;
            // return true (success)]
            *result = sw_malloc_zval();
            ZVAL_TRUE(*result);
        }
        else
        {
            *result = client->response.result_array;
        }
    }

    return ret;
}

static void swoole_mysql_coro_parse_end(mysql_client *client, swString *buffer)
{
    if (client->response.status_code & SW_MYSQL_SERVER_MORE_RESULTS_EXISTS)
    {
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "remaining %ju, more results exists", (uintmax_t) (buffer->length - buffer->offset));
    }
    else
    {
        // no more, clean up
        swString_clear(buffer);
    }
    bzero(&client->response, sizeof(client->response));
    client->statement = NULL;
    client->cmd = SW_MYSQL_COM_NULL;
}

static int swoole_mysql_coro_statement_free(mysql_statement *stmt)
{
    if (stmt->object)
    {
        swoole_set_object(stmt->object, NULL);
        efree(stmt->object);
    }

    if (stmt->buffer)
    {
        swString_free(stmt->buffer);
    }

    if (stmt->result)
    {
        sw_zval_free(stmt->result);
    }

    return SW_OK;
}

static int swoole_mysql_coro_statement_close(mysql_statement *stmt)
{
    // WARNING: it's wrong operation, we send the close statement packet silently, don't change any property in the client!
    // stmt->client->cmd = SW_MYSQL_COM_STMT_CLOSE;

    // call mysql-server to destruct this statement
    swString_clear(mysql_request_buffer);
    bzero(mysql_request_buffer->str, 5);
    //command
    mysql_request_buffer->str[4] = SW_MYSQL_COM_STMT_CLOSE;
    mysql_request_buffer->length = 5;
    char *p = mysql_request_buffer->str;
    p += 5;

    // stmt.id
    mysql_int4store(p, stmt->id);
    p += 4;
    mysql_request_buffer->length += 4;
    //length
    mysql_pack_length(mysql_request_buffer->length - 4, mysql_request_buffer->str);
    //tell sever to close the statement, mysql-server would not reply
    SwooleG.main_reactor->write(SwooleG.main_reactor, stmt->client->fd, mysql_request_buffer->str, mysql_request_buffer->length);

    return SW_OK;
}

static int swoole_mysql_coro_close(zval *zobject)
{
    mysql_client *client = (mysql_client *) swoole_get_object(zobject);
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql_coro");
        return FAILURE;
    }

    if (!client->cli)
    {
        return FAILURE;
    }

    if (client->connected)
    {
        //send quit command
        swString_clear(mysql_request_buffer);
        client->cmd = SW_MYSQL_COM_QUIT;
        bzero(mysql_request_buffer->str, 5);
        mysql_request_buffer->str[4] = SW_MYSQL_COM_QUIT;//command
        mysql_request_buffer->length = 5;
        mysql_pack_length(mysql_request_buffer->length - 4, mysql_request_buffer->str);
        SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length);
        client->connected = 0;
    }

    zend_update_property_bool(swoole_mysql_coro_ce, zobject, ZEND_STRL("connected"), 0);
    SwooleG.main_reactor->del(SwooleG.main_reactor, client->fd);

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, client->fd);
    _socket->object = NULL;
    _socket->active = 0;

    if (client->timer)
    {
        swTimer_del(&SwooleG.timer, client->timer);
        client->timer = NULL;
    }

    if (client->statement_list)
    {
        swLinkedList_node *node = client->statement_list->head;
        while (node)
        {
            mysql_statement *stmt = (mysql_statement *) node->data;
            // after connection closed, mysql stmt cache closed too
            // so we needn't send stmt close command here like pdo.
            swoole_mysql_coro_statement_free(stmt);
            efree(stmt);
            node = node->next;
        }
        swLinkedList_free(client->statement_list);
        client->statement_list = NULL;
    }

    //clear connector
    if (client->connector.timer)
    {
        swTimer_del(&SwooleG.timer, client->connector.timer);
        client->connector.timer = NULL;
    }
    if (client->connector.host)
    {
        efree(client->connector.host);
        client->connector.host = NULL;
    }
    if (client->connector.user)
    {
        efree(client->connector.user);
        client->connector.user = NULL;
    }
    if (client->connector.password)
    {
        efree(client->connector.password);
        client->connector.password = NULL;
    }
    if (client->connector.database)
    {
        efree(client->connector.database);
        client->connector.database = NULL;
    }

    client->cli->close(client->cli);
    swClient_free(client->cli);
    efree(client->cli);
    client->cli = NULL;
    client->state = SW_MYSQL_STATE_CLOSED;
    client->iowait = SW_MYSQL_CORO_STATUS_CLOSED;

    return SUCCESS;
}

static PHP_METHOD(swoole_mysql_coro, __construct)
{
}

static PHP_METHOD(swoole_mysql_coro, __destruct)
{
}

static PHP_METHOD(swoole_mysql_coro, connect)
{
    zval *server_info;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY_EX(server_info, 0, 1)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    HashTable *_ht = Z_ARRVAL_P(server_info);
    zval *value;

    mysql_client *client = (mysql_client *) swoole_get_object(getThis());
    if (client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "connection to the server has already been established");
        RETURN_FALSE;
    }

    mysql_connector *connector = &client->connector;
    zend::string str_host;
    zend::string str_user;
    zend::string str_database;
    zend::string str_password;

    if (php_swoole_array_get_value(_ht, "host", value))
    {
        str_host = value;
        connector->host = str_host.val();
        connector->host_len = str_host.len();
    }
    else
    {
        zend_throw_exception(swoole_mysql_coro_exception_ce, "HOST parameter is required", 11);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "port", value))
    {
        connector->port = zval_get_long(value);
    }
    else
    {
        connector->port = SW_MYSQL_DEFAULT_PORT;
    }
    if (php_swoole_array_get_value(_ht, "user", value))
    {
        str_user = value;
        connector->user = str_user.val();
        connector->user_len = str_user.len();
    }
    else
    {
        zend_throw_exception(swoole_mysql_coro_exception_ce, "USER parameter is required", 11);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "password", value))
    {
        str_password = value;
        connector->password = str_password.val();
        connector->password_len = str_password.len();
    }
    else
    {
        zend_throw_exception(swoole_mysql_coro_exception_ce, "PASSWORD parameter is required", 11);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "database", value))
    {
        str_database = value;
        connector->database = str_database.val();
        connector->database_len = str_database.len();
    }
    else
    {
        zend_throw_exception(swoole_mysql_coro_exception_ce, "DATABASE parameter is required", 11);
        RETURN_FALSE;
    }
    if (php_swoole_array_get_value(_ht, "timeout", value))
    {
        connector->timeout = zval_get_double(value);
    }
    else
    {
        connector->timeout = Socket::default_connect_timeout;
    }
    if (php_swoole_array_get_value(_ht, "charset", value))
    {
        zend::string str_charset(value);
        connector->character_set = mysql_get_charset(str_charset.val());
        if (connector->character_set < 0)
        {
            char buf[64];
            snprintf(buf, sizeof(buf), "unknown charset [%s]", str_charset.val());
            zend_throw_exception(swoole_mysql_coro_exception_ce, buf, 11);
            RETURN_FALSE;
        }
    }
    else
    {
        connector->character_set = SW_MYSQL_DEFAULT_CHARSET;
    }

    if (php_swoole_array_get_value(_ht, "strict_type", value))
    {
        connector->strict_type = zval_is_true(value);
    }

    if (php_swoole_array_get_value(_ht, "fetch_mode", value))
    {
        connector->fetch_mode = zval_is_true(value);
    }

    swClient *cli = (swClient *) emalloc(sizeof(swClient));
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
    if (!swReactor_handle_isset(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL_CORO))
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_READ, swoole_mysql_coro_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_WRITE, swoole_mysql_coro_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_ERROR, swoole_mysql_coro_onError);
    }

    if (swClient_create(cli, type, 0) < 0)
    {
        swoole_php_sys_error(E_WARNING, "swClient_create() failed");
        _failed:
        if (errno != 0)
        {
            SwooleG.error = errno;
        }
        zend_update_property_string(swoole_mysql_coro_ce, getThis(), ZEND_STRL("connect_error"), swoole_strerror(SwooleG.error));
        zend_update_property_long(swoole_mysql_coro_ce, getThis(), ZEND_STRL("connect_errno"), SwooleG.error);
        efree(cli);
        RETURN_FALSE;
    }

    //tcp nodelay
    if (type != SW_SOCK_UNIX_STREAM)
    {
        int tcp_nodelay = 1;
        if (setsockopt(cli->socket->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) != 0)
        {
            swoole_php_sys_error(E_WARNING, "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY) failed", cli->socket->fd);
        }
    }

    errno = 0;
    int ret = cli->connect(cli, connector->host, connector->port, -1, 2);
    if ((ret < 0 && errno == EINPROGRESS) || ret == 0)
    {
        if (SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_WRITE) < 0)
        {
            goto _failed;
        }
    }
    else
    {
        goto _failed;
    }

    zend_update_property(swoole_mysql_coro_ce, getThis(), ZEND_STRL("serverInfo"), server_info);
    zend_update_property_long(swoole_mysql_coro_ce, getThis(), ZEND_STRL("sock"), cli->socket->fd);

    if (!client->buffer)
    {
        client->buffer = swString_new(SW_BUFFER_SIZE_BIG);
    }
    else
    {
        swString_clear(client->buffer);
        bzero(&client->response, sizeof(client->response));
    }
    client->fd = cli->socket->fd;
    client->object = getThis();
    client->cli = cli;
    sw_copy_to_stack(client->object, client->_object);

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, cli->socket->fd);
    _socket->object = client;
    _socket->active = 0;

    php_coro_context *context = (php_coro_context *) swoole_get_property(getThis(), 0);
    if (!context)
    {
        context = (php_coro_context *) emalloc(sizeof(php_coro_context));
        swoole_set_property(getThis(), 0, context);
    }
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->coro_params = *getThis();

    connector->host = estrndup(connector->host, connector->host_len);
    connector->user = estrndup(connector->user, connector->user_len);
    connector->password = estrndup(connector->password, connector->password_len);
    connector->database = estrndup(connector->database, connector->database_len);

    if (connector->timeout > 0)
    {
        connector->timer = swTimer_add(&SwooleG.timer, (long) (connector->timeout * 1000), 0, context, swoole_mysql_coro_onConnectTimeout);
    }
    client->cid = PHPCoroutine::get_cid();
    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_mysql_coro, query)
{
    swString sql;
    bzero(&sql, sizeof(sql));

    mysql_client *client = (mysql_client *) swoole_get_object(getThis());
    if (!client || client->state == SW_MYSQL_STATE_CLOSED)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        zend_update_property_long(swoole_mysql_coro_ce, getThis(), ZEND_STRL("errCode"), SwooleG.error);
        swoole_php_fatal_error(E_WARNING, "The MySQL connection is not established");
        RETURN_FALSE;
    }

    if (client->iowait == SW_MYSQL_CORO_STATUS_DONE)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting for calling recv, cannot send new sql query");
        RETURN_FALSE;
    }

    PHPCoroutine::check_bind("mysql client", client->cid);

    double timeout = Socket::default_read_timeout;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|d", &sql.str, &sql.length, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (sql.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty");
        RETURN_FALSE;
    }

    if (mysql_query(getThis(), client, &sql, NULL) < 0)
    {
        RETURN_FALSE;
    }

    client->state = SW_MYSQL_STATE_READ_START;
    php_coro_context *context = (php_coro_context *) swoole_get_property(getThis(), 0);
    if (timeout > 0)
    {
        client->timer = swTimer_add(&SwooleG.timer, (long) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
        if (client->timer && client->defer)
        {
            context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
        }
    }
    if (client->defer)
    {
        client->iowait = SW_MYSQL_CORO_STATUS_WAIT;
        RETURN_TRUE;
    }
    client->suspending = 1;
    client->cid = PHPCoroutine::get_cid();
    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_mysql_coro, nextResult)
{
    mysql_client *client = (mysql_client *) swoole_get_object(getThis());
    if (!client)
    {
        RETURN_FALSE;
    }

    if (client->buffer && (size_t) client->buffer->offset < client->buffer->length)
    {
        client->cmd = SW_MYSQL_COM_QUERY;
        client->state = SW_MYSQL_STATE_READ_START;
        client->statement = nullptr;
        zval *result = NULL;
        if (swoole_mysql_coro_parse_response(client, &result, 1) == SW_OK)
        {
            swoole_mysql_coro_parse_end(client, client->buffer); // ending tidy up
            zval _result = *result;
            efree(result);
            result = &_result;
            RETURN_ZVAL(result, 0, 1);
        }
        else
        {
            RETURN_FALSE;
        }
    }
    else
    {
        RETURN_NULL();
    }
}

static void swoole_mysql_coro_query_transcation(const char* command, uint8_t in_transaction, zend_execute_data *execute_data, zval *return_value)
{
    mysql_client *client = (mysql_client *) swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql");
        RETURN_FALSE;
    }

    PHPCoroutine::check_bind("mysql client", client->cid);

    // we deny the dangerous operation of transaction
    // if developers need use defer to begin transaction, they can use query("begin/commit/rollback") with defer
    // to make sure they know what they are doing
    if (unlikely(client->defer))
    {
        swoole_php_fatal_error(
            E_DEPRECATED,
            "you should not use defer to handle transaction, "
            "if you want, please use `query` instead"
        );
        RETURN_FALSE;
    }

    if (in_transaction && client->transaction)
    {
        zend_throw_exception(swoole_mysql_coro_exception_ce, "There is already an active transaction", 21);
        RETURN_FALSE;
    }

    if (!in_transaction && !client->transaction)
    {
        zend_throw_exception(swoole_mysql_coro_exception_ce, "There is no active transaction", 22);
        RETURN_FALSE;
    }

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, command, strlen(command));
    if (mysql_query(getThis(), client, &sql, NULL) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        double timeout = Socket::default_read_timeout;
        if (zend_parse_parameters(ZEND_NUM_ARGS(), "|d", &timeout) == FAILURE)
        {
            RETURN_FALSE;
        }
        php_coro_context *context = (php_coro_context *) swoole_get_property(getThis(), 0);
        if (timeout > 0)
        {
            client->timer = swTimer_add(&SwooleG.timer, (long) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
        }
        client->cid = PHPCoroutine::get_cid();
        // coro_use_return_value
        *(zend_uchar *) &execute_data->prev_execute_data->opline->result_type = IS_VAR;
        PHPCoroutine::yield_m(return_value, context);
        // resume true
        if (Z_BVAL_P(return_value))
        {
            client->transaction = in_transaction;
        }
    }
}

static PHP_METHOD(swoole_mysql_coro, begin)
{
    swoole_mysql_coro_query_transcation("BEGIN", 1, execute_data, return_value);
}

static PHP_METHOD(swoole_mysql_coro, commit)
{
    swoole_mysql_coro_query_transcation("COMMIT", 0, execute_data, return_value);
}

static PHP_METHOD(swoole_mysql_coro, rollback)
{
    swoole_mysql_coro_query_transcation("ROLLBACK", 0, execute_data, return_value);
}

static PHP_METHOD(swoole_mysql_coro, getDefer)
{
    mysql_client *client = (mysql_client *) swoole_get_object(getThis());
    RETURN_BOOL(client->defer);
}

static PHP_METHOD(swoole_mysql_coro, setDefer)
{
    zend_bool defer = 1;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &defer) == FAILURE)
    {
        RETURN_FALSE;
    }

    mysql_client *client = (mysql_client *) swoole_get_object(getThis());
    if (client->iowait > SW_MYSQL_CORO_STATUS_READY)
    {
        RETURN_BOOL(defer);
    }
    client->defer = defer;
    RETURN_TRUE
}

static sw_inline size_t get_string_sw_malloc_size(char* source) 
{
    size_t source_size = 0;
    memcpy(&source_size, source - 4, sizeof(size_t));
    return source_size;
}

char* sw_multi_memcpy_auto_realloc(char** source, int n_value, ...) 
{
    int source_size = get_string_sw_malloc_size(*source);

    va_list var_arg;
    int count = 0;
    int dest_len = strlen(*source) + 1;
    va_start(var_arg, n_value);
    while (count < n_value) {
        char *tmp = va_arg(var_arg, char*);
        dest_len += strlen(tmp);
        count++;
    }
    va_end(var_arg);

    //need realloc
    char* dest = NULL;
    if (source_size < (int)MM_REAL_SIZE(dest_len)) {
        sw_string_malloc_32(&dest, dest_len);
        memcpy(dest, *source, strlen(*source));
        sw_string_free_32(*source);
        *source = dest;
    } else {
        dest = *source;
    }

    count=0;
    va_start(var_arg, n_value);
    while (count < n_value) {
        char *tmp = va_arg(var_arg, char*);
        memcpy(dest + strlen(dest), tmp, strlen(tmp));
        count++;
    }
    va_end(var_arg);
    return dest;
}

//match table and alias
static int preg_table_match(char* key, char* table, char* alias) 
{
    int table_start = -1;
    int table_end = -1;
    int alias_start = -1;
    int alias_end = -1;

    int key_len;
    key_len = strlen(key);

    table[0] = '\0';
    alias[0] = '\0';

    if (key_len == 0) {
        return 0;
    }

    int i = -1;
    while (i < key_len) {
        i++;
        char c_key = key[i];
        if ( table_start == -1 && !sw_is_space(c_key)) {
            table_start = i;
        }

        if (table_end == -1 && (c_key == '(' || sw_is_space(c_key))) {
            table_end = i;
        }

        if ( alias_start == -1 && c_key == '(') {
            alias_start = i;
        }

        if ( alias_end == -1 && c_key == ')') {
            alias_end = i;
        }
    }

    if (alias_start == -1 || alias_end == -1 || alias_start > alias_end) {
        table_end = key_len;
    }

    if (table_start != -1 && table_end != -1 && table_end > table_start) {
        if (table_end - table_start >= MAX_TABLE_SIZE) {
            swoole_php_fatal_error(E_ERROR, "table size is too long, [%s]", key);
        }

        memset(table, 0, MAX_TABLE_SIZE);
        memcpy(table, key + table_start, table_end - table_start);
    }

    if (alias_start != -1 && alias_end != -1 && alias_end > alias_start) {
        if (alias_end - alias_start >= MAX_TABLE_SIZE) {
            swoole_php_fatal_error(E_ERROR, "alias size is too long, [%s]", key);
        }

        memset(alias, 0, MAX_TABLE_SIZE);
        memcpy(alias, key + alias_start + 1, alias_end - alias_start - 1);
    }

    return 1;
}

char* sw_get_array_key_index(zval *p, uint32_t index) 
{
    if (!SW_IS_ARRAY(p)) {
        return NULL;
    }

    uint32_t array_size = zend_hash_num_elements(Z_ARRVAL_P(p));
    if (array_size < index) {
        return NULL;
    }

    char * key;
    zval *value;
    uint32_t key_len;
    int key_type;
    ulong_t num = 0;

    SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(p), key, key_len, key_type, value)
    if (HASH_KEY_IS_STRING != key_type) { //not char
        continue;
    }

    if ( value == NULL || key_len == 0) {}

    if (num == index) {
        return key;
    }

    num++;
    SW_HASHTABLE_FOREACH_END();
    return NULL;
}

int sw_strpos(const char* haystack,const char* needle) 
{
    int ignorecase = 0;
    register unsigned char c, needc;
    unsigned char const *from, *end;
    int len = strlen(haystack);
    int needlen = strlen(needle);
    from = (unsigned char *)haystack;
    end = (unsigned char *)haystack + len;
    const char *findreset = needle;

    int i = 0;

    while (from < end) {
        c = *from++;
        needc = *needle;
        if (ignorecase) {
            if (c >= 65 && c < 97)
                c += 32;
            if (needc >= 65 && needc < 97)
                needc += 32;
        }
        if (c == needc) {
            ++needle;
            if (*needle == '\0') {
                if (len == needlen)
                    return 0;
                else
                    return i - needlen+1;
            }
        } else {
            if (*needle == '\0' && needlen > 0)
                return i - needlen +1;
            needle = findreset;
        }
        i++;
    }
    return  -1;
}

static int preg_join_match(char* key, char* join, char* table, char* alias) 
{
    int join_start = -1;
    int join_end = -1;
    int table_start = -1;
    int table_end = -1;
    int alias_start = -1;
    int alias_end = -1;

    int key_len = strlen(key);

    join[0] = '\0';
    table[0] = '\0';
    alias[0] = '\0';

    if (key_len == 0) {
        return 0;
    }

    int i = -1;
    while (i < key_len) {
        i++;
        char c_key = key[i];
        if ( join_start == -1 && c_key == '[') {
            join_start = i;
        }

        if (table_start == -1 && join_start == -1 && c_key != '[' && !sw_is_space(c_key)) {
            table_start = i;
        }

        if (join_end != -1 && table_start == -1 && !sw_is_space(c_key)) {
            table_start = i;
        }

        if ( join_start != -1 && c_key == ']') {
            join_end = i;
        }

        if (table_start != -1 && c_key == '(') {
            table_end = i;
        }

        if ( alias_start == -1 && c_key == '(') {
            alias_start = i;
        }

        if ( alias_end == -1 && c_key == ')') {
            alias_end = i;
        }
    }

    if (alias_start == -1 || alias_end == -1 || alias_start > alias_end) {
        table_end = key_len;
    }

    if (table_start != -1 && table_end != -1 && table_end > table_start) {
        if (table_end - table_start >= MAX_TABLE_SIZE) {
            swoole_php_fatal_error(E_ERROR, "join table size is too long, [%s]", key);
        }

        memset(table, 0, MAX_TABLE_SIZE);
        memcpy(table, key + table_start, table_end - table_start);
    }

    if (alias_start != -1 && alias_end != -1 && alias_end > alias_start) {
        if (alias_end - alias_start >= MAX_TABLE_SIZE) {
            swoole_php_fatal_error(E_ERROR, "join alias size is too long, [%s]", key);
        }

        memset(alias, 0, MAX_TABLE_SIZE);
        memcpy(alias, key + alias_start + 1, alias_end - alias_start - 1);
    }

    if (join_start != -1 && join_end != -1 && join_start < join_end) {
        if (join_end - join_start >= MAX_OPERATOR_SIZE) {
            swoole_php_fatal_error(E_ERROR, "join operator size is too long, [%s]", key);
        }

        memset(join, 0, MAX_OPERATOR_SIZE);
        memcpy(join, key + join_start + 1, join_end - join_start - 1);
        if (!(strcmp(join, ">") == 0 || strcmp(join, "<") == 0 || strcmp(join, "<>") == 0 || strcmp(join, "><") == 0)) {
            join[0] = '\0';
        }
    }
    return 1;
}

static const char* get_join_type(char* type) 
{
    if (strcmp(type, "<") == 0) {
        return "LEFT";
    } else if (strcmp(type, ">") == 0) {
        return "RIGHT";
    } else if (strcmp(type, "<>") == 0) {
        return "FULL";
    } else if (strcmp(type, "><") == 0) {
        return "INNER";
    } else {
        return "";
    }
}

static int is_set_array_index(HashTable *ht, int index) {
    zval* p = zend_hash_index_find(ht, index);
    if (SW_IS_EMPTY(p)) {
        return 0;
    } else {
        return 1;
    }
}

static char* strreplace(char* original, char const * const pattern, char const * const replacement) 
{
    size_t const replen = strlen(replacement);
    size_t const patlen = strlen(pattern);
    size_t const orilen = strlen(original);

    size_t patcnt = 0;
    const char * oriptr;
    const char * patloc;

    for (oriptr = original; (patloc = strstr(oriptr, pattern)); oriptr = patloc + patlen) {
        patcnt++;
    }

    size_t const retlen = orilen + patcnt * (replen - patlen);
    char * const returned = (char *) sw_malloc( sizeof(char) * (retlen + 1) );

    if (returned != NULL) {
        char * retptr = returned;
        for (oriptr = original; (patloc = strstr(oriptr, pattern)); oriptr = patloc + patlen) {
            size_t const skplen = patloc - oriptr;
            strncpy(retptr, oriptr, skplen);
            retptr += skplen;
            strncpy(retptr, replacement, replen);
            retptr += replen;
        }
        strcpy(retptr, oriptr);
    }

    strcpy(original, returned);
    sw_free(returned);
    return original;
}

static char* sw_implode(zval *arr, const char *delim_str, char** result) 
{
    zval *return_value = NULL;
    SW_MAKE_STD_ZVAL(return_value);
    zend_string *delim = zend_string_init(delim_str, strlen(delim_str), 0);

    php_implode(delim, arr, return_value);

    sw_multi_memcpy_auto_realloc(result, 1, Z_STRVAL_P(return_value));

    efree(delim);
    zval_ptr_dtor(return_value);

    return *result;
}

static char* column_quote(char* string, char* table_column) 
{
    char tmp[MAX_TABLE_SIZE] = {0};

    sprintf(tmp, " `%s` ", string);

    if (strlen(tmp) >= MAX_TABLE_SIZE) {
        swoole_php_fatal_error(E_ERROR, "column size is too long, [%s]", string);
    }

    if (sw_strpos(tmp, ".") >= 0) {
        if (strlen(tmp) + 5 >= MAX_TABLE_SIZE) {
            swoole_php_fatal_error(E_ERROR, "column + alias size is too long, [%s]", string);
        }
        strreplace(tmp, ".", "`.`");
    }

    strcpy(table_column, tmp);
    return table_column;
}

static char *rtrim(char *str) 
{
    if (str == NULL || *str == '\0') {
        return str;
    }

    int len = strlen(str);
    char *p = str + len - 1;
    while (p >= str  && (isspace(*p) || (*p) == '\n' || (*p) == '\r' || (*p) == '\t')) {
        *p = '\0';
        --p;
    }
    return str;
}

static char *ltrim(char *str) 
{
    if (str == NULL || *str == '\0') {
        return str;
    }

    int len = 0;
    char *p = str;
    while (*p != '\0' && (isspace(*p) || (*p) == '\n' || (*p) == '\r' || (*p) == '\t')) {
        ++p;
        ++len;
    }

    memmove(str, p, strlen(str) - len + 1);

    return str;
}

static char *trim(char *str) 
{
    str = rtrim(str);
    str = ltrim(str);
    return str;
}

static char* rtrim_str(char *str, char *remove) 
{
    if (str == NULL || *str == '\0') {
        return str;
    }

    int len = strlen(str);
    int r_len = strlen(remove);

    if (r_len > len) {
        return str;
    }

    char *end = str + len - 1;
    char *r_end = remove + r_len - 1;

    int remove_flag = 1;

    while (end >= str && r_end >= remove) {
        if ((*r_end) == (*end)) {
            --r_end;
            --end;
        } else {
            remove_flag = 0;
            break;
        }
    }

    if (remove_flag) {
        char *end = str + len - 1;
        char *r_end = remove + r_len - 1;
        while (end >= str && r_end >= remove) {
            if ((*r_end) == (*end)) {
                *end = '\0';
                --r_end;
                --end;
            } else {
                break;
            }
        }
    }

    return str;
}

static char *ltrim_str(char *str, char *remove) 
{
    if (str == NULL || *str == '\0') {
        return str;
    }

    int len = strlen(str);
    int r_len = strlen(remove);

    if (r_len > len) {
        return str;
    }

    char *end = str + len - 1;
    char *r_end = remove + r_len - 1;

    char *start = str;
    char *r_start = remove;

    int remove_flag = 1;
    while (start <= end && r_start <= r_end) {
        if ((*start) == (*r_start)) {
            ++r_start;
            ++start;
        } else {
            remove_flag = 0;
            break;
        }
    }

    if (remove_flag) {
        memmove(str, start, len - r_len);
        str[len - r_len] = '\0';
    }

    return str;
}

static zval* php_sw_array_get_value(HashTable *ht, char *key) 
{
    zval *v = zend_hash_str_find(ht, key, strlen(key));
    if (v == NULL) {
        return NULL;
    } else {
        if (ZVAL_IS_NULL(v)) {
            return NULL;
        } else {
            return v;
        }
    }
}

static char* handle_join(zval *join, char *table, char** table_query) 
{
    char* sub_table;
    zval* relation;
    uint32_t key_len;
    int key_type;

    SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(join), sub_table, key_len, key_type, relation)
    if (HASH_KEY_IS_STRING != key_type) {
        continue;
    }

    if (key_len == 0) {}

    char join_join[MAX_TABLE_SIZE] = {0};
    char join_table[MAX_TABLE_SIZE] = {0};
    char join_alias[MAX_TABLE_SIZE] = {0};
    preg_join_match(sub_table, join_join, join_table, join_alias);

    if (!sw_is_string_empty(join_join) && !sw_is_string_empty(join_table)) {
        sw_multi_memcpy_auto_realloc(table_query, 5, " ", get_join_type(join_join), " JOIN `", join_table, "` ");

        if (!sw_is_string_empty(join_alias)) {
            sw_multi_memcpy_auto_realloc(table_query, 3, "AS `", join_alias, "` ");
        }

        if (Z_TYPE_P(relation) == IS_STRING) {
            sw_multi_memcpy_auto_realloc(table_query, 3, "USING (`", Z_STRVAL_P(relation), "`) ");
        } else if (Z_TYPE_P(relation) == IS_ARRAY) {
            if (is_set_array_index(Z_ARRVAL_P(relation), 0)) {
                sw_multi_memcpy_auto_realloc(table_query, 1, "USING (`");
                sw_implode(relation, "`,`", table_query);
                sw_multi_memcpy_auto_realloc(table_query, 1, "`) ");
            } else {
                char *key;
                zval *value;

                sw_multi_memcpy_auto_realloc(table_query, 1, "ON ");

                SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(relation), key, key_len, key_type, value)
                if (HASH_KEY_IS_STRING != key_type) {
                    continue;
                }

                char* table_column = NULL;
                sw_string_malloc_32(&table_column, 0);
                if (sw_strpos(key, ".") >= 0) {
                    column_quote(key, table_column);
                } else {
                    sw_multi_memcpy_auto_realloc(&table_column, 5, "`", table, "`.`", key, "`");
                }

                //alias
                if (!sw_is_string_empty(join_alias)) {
                    sw_multi_memcpy_auto_realloc(table_query, 4, table_column, "=`", join_alias, "`");
                } else {
                    sw_multi_memcpy_auto_realloc(table_query, 4, table_column, "= `", join_table, "`");
                }

                sw_string_free_32(table_column);

                sw_multi_memcpy_auto_realloc(table_query, 3, ".`", Z_STRVAL_P(value), "` AND");
                SW_HASHTABLE_FOREACH_END();

                char str[10] = "AND";
                rtrim_str(rtrim(*table_query), str);
            }
        }
    }
    SW_HASHTABLE_FOREACH_END();


    return *table_query;
}

static char* column_push(zval* columns, zval* map, char** column_query) 
{
    if (SW_IS_EMPTY(columns) || (Z_TYPE_P(columns) == IS_STRING && strcmp(Z_STRVAL_P(columns), "*") == 0)) {
        sw_multi_memcpy_auto_realloc(column_query, 1, "*");
        return *column_query;
    }

    if (Z_TYPE_P(columns) == IS_STRING) {
        sw_multi_memcpy_auto_realloc(column_query, 1, Z_STRVAL_P(columns));
        return *column_query;
    } else if (SW_IS_ARRAY(columns)) {
        char * key;
        zval *value;
        uint32_t key_len;
        int key_type;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(columns), key, key_len, key_type, value)
        if (Z_TYPE_P(value) != IS_STRING) {
            continue;
        }

        if ( key == NULL || key_len == 0 || key_type == 0) {}

        char match_column[MAX_TABLE_SIZE] = {0};
        char match_alias[MAX_TABLE_SIZE] = {0};
        preg_table_match(Z_STRVAL_P(value), match_column, match_alias);

        if (!sw_is_string_empty(match_column) && !sw_is_string_empty(match_alias)) {
            sw_multi_memcpy_auto_realloc(column_query, 4, match_column, " AS `", match_alias, "`,");
        } else {
            sw_multi_memcpy_auto_realloc(column_query, 2, Z_STRVAL_P(value), ",");
        }

        SW_HASHTABLE_FOREACH_END();

        char tmp[2] = ",";
        rtrim_str(rtrim(*column_query), tmp);
        return *column_query;
    } else {
        sw_multi_memcpy_auto_realloc(column_query, 1, "*");
        return *column_query;
    }
}

static int preg_and_or_match(char* key, char* relation) 
{
    int relation_start = -1;
    int relation_end = -1;

    relation[0] = '\0';

    int key_len = strlen(key);
    if (key_len == 0) {
        return 0;
    }

    int i = -1;
    while (i < key_len) {
        i++;
        char c_key = key[i];

        if ( relation_start == -1 && !sw_is_space(c_key)) {
            relation_start = i;
        }

        if (relation_end == -1 && ( c_key == '#' || sw_is_space(c_key))) {
            relation_end = i;
        }

        if (relation_end == -1 && i == key_len - 1) {
            relation_end = key_len;
        }
    }

    if (relation_start != -1 && relation_end != -1 && relation_end > relation_start && relation_end - relation_start - 1 < MAX_OPERATOR_SIZE) {
        memset(relation, 0, MAX_OPERATOR_SIZE);
        memcpy(relation, key + relation_start, relation_end - relation_start);
        if (strcmp(relation, "AND") != 0 && strcmp(relation, "OR") != 0 && strcmp(relation, "and") != 0 && strcmp(relation, "or") != 0 ) {
            relation[0] = '\0';
        }
    }

    return 1;
}

static int preg_operator_match(char* key, char* column, char* operators) 
{
    int column_start = -1;
    int column_end = -1;
    int column_end_is_space = -1;
    int operator_start = -1;
    int operator_end = -1;

    int key_len = strlen(key);

    column[0] = '\0';
    operators[0] = '\0';

    if (key_len == 0) {
        return 0;
    }

    int i = -1;
    while (i < key_len) {
        i++;
        char c_key = key[i];
        if ( column_start == -1 && !sw_is_space(c_key)) {
            column_start = i;
        }

        if (column_end == -1 && (c_key == '[' || sw_is_space(c_key))) {
            column_end = i;
        }

        if (column_end_is_space == -1 && sw_is_space(c_key)) {
            column_end_is_space = i;
        }

        if ( operator_start == -1 && c_key == '[') {
            operator_start = i;
        }

        if ( operator_end == -1 && c_key == ']') {
            operator_end = i;
        }
    }

    if (operator_start == -1 || operator_end == -1 || operator_start > operator_end) {
        column_end = column_end_is_space == -1 ? key_len : column_end_is_space;
    }

    if (column_start != -1 && column_end != -1 && column_end > column_start) {
        if (column_end - column_start - 1 >= MAX_TABLE_SIZE) {
            swoole_php_fatal_error(E_ERROR, "column size is too long [%s]", key);
        }

        memset(column, 0, MAX_TABLE_SIZE);
        memcpy(column, key + column_start, column_end - column_start);
    }

    if (operator_start != -1 && operator_end != -1 && operator_start < operator_end) {
        if (operator_end - operator_start - 1 >= MAX_OPERATOR_SIZE) {
            swoole_php_fatal_error(E_ERROR, "operator size is too long [%s]", key);
        }

        memset(operators, 0, MAX_OPERATOR_SIZE);
        memcpy(operators, key + operator_start + 1, operator_end - operator_start - 1);
        if (!(strcmp(operators, ">") == 0 || strcmp(operators, ">=") == 0 || strcmp(operators, "<") == 0 || strcmp(operators, "<=") == 0 ||
                strcmp(operators, "!") == 0 || strcmp(operators, "~") == 0 || strcmp(operators, "!~") == 0 || strcmp(operators, "<>") == 0 || strcmp(operators, "><") == 0)) {
            operators[0] = '\0';
        }
    }

    return 1;
}

static zval* add_map(zval* map, zval* value) 
{
    zval *copy = sw_zval_copy(value);
    add_next_index_zval(map, copy);
    return map;
}

static char* handle_where_not_in(zval* not_in_array, char** where_query, zval* map) 
{
    char * key;
    zval *value;
    uint32_t key_len;
    int key_type;

    SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(not_in_array), key, key_len, key_type, value)
    if (Z_TYPE_P(value) == IS_STRING || Z_TYPE_P(value) == IS_LONG) {
        add_map(map, value);
        sw_multi_memcpy_auto_realloc(where_query, 1, " ?,");
    }

    if ( key == NULL || key_len == 0 || key_type == 0) {}

    SW_HASHTABLE_FOREACH_END();

    char tmp[2] = ",";
    rtrim_str(rtrim(*where_query), tmp);
    return *where_query;
}

static char* handle_like_array(zval* like_array, char** where_query, char* column, char* operators, zval* map, char* connector) 
{
    char * key;
    zval *value;
    uint32_t key_len;
    int key_type;

    SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(like_array), key, key_len, key_type, value)
    if (Z_TYPE_P(value) == IS_STRING || Z_TYPE_P(value) == IS_LONG) {
        add_map(map, value);
        sw_multi_memcpy_auto_realloc(where_query, 3, column, strcmp(operators, "~") == 0 ? "LIKE ? " : "NOT LIKE ? ", connector);
    }

    if ( key == NULL || key_len == 0 || key_type == 0) {}

    SW_HASHTABLE_FOREACH_END();
    rtrim_str(rtrim(*where_query), connector);
    return *where_query;
}

//where condition
static char* where_implode(char* key, zval* value, zval* map, char** where_query, char* connector) 
{
    char relation_ship[MAX_OPERATOR_SIZE] = {0};
    preg_and_or_match(key, relation_ship);

    if (Z_TYPE_P(value) == IS_ARRAY && !sw_is_string_empty(relation_ship)) {
        char* relation_key;
        zval* relation_value;
        uint32_t relation_key_len;
        int relation_key_type;

        char* sub_where_clause = NULL;
        sw_string_malloc_32(&sub_where_clause, 0);

        sw_multi_memcpy_auto_realloc(where_query, 1, " AND (");

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(value), relation_key, relation_key_len, relation_key_type, relation_value)
        if (HASH_KEY_IS_STRING != relation_key_type) {
            continue;
        } else {
            where_implode(relation_key, relation_value, map, &sub_where_clause, relation_ship);
        }

        if (relation_key_len == 0) {}

        SW_HASHTABLE_FOREACH_END();

        sw_multi_memcpy_auto_realloc(where_query, 2, sub_where_clause, ")");
        sw_string_free_32(sub_where_clause);
        return *where_query;
    }

    char column[MAX_TABLE_SIZE] = {0};
    char operators[MAX_OPERATOR_SIZE] = {0};
    preg_operator_match(key, column, operators);

    if (!sw_is_string_empty(column)) {
        column_quote(column, column);

        if (!sw_is_string_empty(operators)) {
            if (strcmp(operators, ">") == 0 || strcmp(operators, ">=") == 0 || strcmp(operators, "<") == 0 || strcmp(operators, "<=") == 0) { // >, >=, <, <=
                add_map(map, value);
                sw_multi_memcpy_auto_realloc(where_query, 4, connector, column, operators, " ? ");
            } else if (strcmp(operators, "!") == 0) { //not equal
                switch (Z_TYPE_P(value)) {
                case IS_NULL:
                    sw_multi_memcpy_auto_realloc(where_query, 3, connector, column, "IS NOT NULL ");
                    break;
                case IS_ARRAY:
                    sw_multi_memcpy_auto_realloc(where_query, 3, connector, column, "NOT IN (");
                    handle_where_not_in(value, where_query, map);
                    sw_multi_memcpy_auto_realloc(where_query, 1, ") ");
                    break;
                case IS_LONG:
                case IS_STRING:
                case IS_DOUBLE:
                case IS_TRUE:
                case IS_FALSE:
                    add_map(map, value);
                    sw_multi_memcpy_auto_realloc(where_query, 3, connector, column, "!= ? ");
                    break;
                }
            } else if (strcmp(operators, "~") == 0 ||  strcmp(operators, "!~") == 0) { //like
                if (Z_TYPE_P(value) == IS_STRING) {
                    add_map(map, value);
                    sw_multi_memcpy_auto_realloc(where_query, 3, connector, column, (strcmp(operators, "~") == 0 ? "LIKE ? " : "NOT LIKE ? "));
                } else if (Z_TYPE_P(value) == IS_ARRAY) {
                    char* like_connector = sw_get_array_key_index(value, 0);
                    if (like_connector != NULL && (strcmp(like_connector, "AND") == 0 || strcmp(like_connector, "OR") == 0)) {
                        zval* connetor_value = php_sw_array_get_value(Z_ARRVAL_P(value), like_connector);
                        if (connetor_value != NULL && Z_TYPE_P(connetor_value) == IS_ARRAY) {
                            sw_multi_memcpy_auto_realloc(where_query, 2, connector, " (");
                            handle_like_array(connetor_value, where_query, column, operators, map, like_connector);
                            sw_multi_memcpy_auto_realloc(where_query, 1, ") ");
                        }
                    } else {
                        sw_multi_memcpy_auto_realloc(where_query, 2, connector, " (");
                        char op_tmp[10] = "OR";
                        handle_like_array(value, where_query, column, operators, map, op_tmp);
                        sw_multi_memcpy_auto_realloc(where_query, 1, ") ");
                    }
                }
            } else if (strcmp(operators, "<>") == 0 ||  strcmp(operators, "><") == 0) {
                if (Z_TYPE_P(value) == IS_ARRAY) {
                    zval* between_a = zend_hash_index_find(Z_ARRVAL_P(value), 0);
                    zval* between_b = zend_hash_index_find(Z_ARRVAL_P(value), 1);
                    if (!SW_IS_EMPTY(between_a) && (Z_TYPE_P(between_a) == IS_LONG || Z_TYPE_P(between_a) == IS_STRING)
                            && !SW_IS_EMPTY(between_b) && (Z_TYPE_P(between_b) == IS_LONG || Z_TYPE_P(between_b) == IS_STRING)) {
                        sw_multi_memcpy_auto_realloc(where_query, 2, connector, " ");
                        if (strcmp(operators, "><") == 0) {
                            sw_multi_memcpy_auto_realloc(where_query, 1, "NOT ");
                        }

                        add_map(map, between_a);
                        sw_multi_memcpy_auto_realloc(where_query, 3, "(", column, "BETWEEN ? ");
                        add_map(map, between_b);
                        sw_multi_memcpy_auto_realloc(where_query, 1, "AND ?) ");
                    }
                }
            }
        } else {
            switch (Z_TYPE_P(value)) {
            case IS_NULL:
                sw_multi_memcpy_auto_realloc(where_query, 3, connector, column, "IS NULL ");
                break;
            case IS_ARRAY:
                sw_multi_memcpy_auto_realloc(where_query, 3, connector, column, "IN (");
                handle_where_not_in(value, where_query, map);
                sw_multi_memcpy_auto_realloc(where_query, 1, ") ");
                break;
            case IS_LONG:
            case IS_STRING:
            case IS_DOUBLE:
            case IS_TRUE:
            case IS_FALSE:
                add_map(map, value);
                sw_multi_memcpy_auto_realloc(where_query, 3, connector, column, "= ? ");
                break;
            }
        }
    }

    ltrim_str(*where_query, connector);
    return *where_query;
}

//handle group by
static char* group_by_implode(zval* group, char** group_by_condition) 
{
    if (!SW_IS_EMPTY(group)) {
        if (Z_TYPE_P(group) == IS_STRING) {
            sw_multi_memcpy_auto_realloc(group_by_condition, 1, Z_STRVAL_P(group));
        } else if (Z_TYPE_P(group) == IS_ARRAY) {
            char* key;
            zval* value;
            uint32_t key_len;
            int key_type;


            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(group), key, key_len, key_type, value)
            if (Z_TYPE_P(value) == IS_STRING) {
                sw_multi_memcpy_auto_realloc(group_by_condition, 2, Z_STRVAL_P(value), ",");
            }

            if ( key == NULL || key_len == 0 || key_type == 0) {}

            SW_HASHTABLE_FOREACH_END();

            char* tmp = (*group_by_condition) +  strlen(*group_by_condition) - 1;
            if (*tmp == ',') {
                *tmp = '\0';
            }
        }
    }
    return *group_by_condition;
}

//handle having
char* having_implode(zval* having, zval* map, char** having_condition) 
{
    char tmp[5] = "AND";

    if (SW_IS_ARRAY(having)) {
        char * key;
        zval *value;
        uint32_t key_len;
        int key_type;

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(having), key, key_len, key_type, value)
        if (HASH_KEY_IS_STRING != key_type) {
            continue;
        } else {
            where_implode(key, value, map, having_condition, tmp);
        }

        if (key_len == 0) {}

        SW_HASHTABLE_FOREACH_END();
    }

    strreplace(*having_condition, "( AND", "(");
    trim(ltrim_str(ltrim(*having_condition), tmp));
    return *having_condition;
}

//order by
char* order_implode(zval* order, char** order_condition) 
{
    if (!SW_IS_EMPTY(order)) {
        if (Z_TYPE_P(order) == IS_STRING) {
            sw_multi_memcpy_auto_realloc(order_condition, 1, Z_STRVAL_P(order));
        } else if (Z_TYPE_P(order) == IS_ARRAY) {
            char* key;
            zval* value;
            uint32_t key_len;
            int key_type;

            SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(order), key, key_len, key_type, value)
            if (HASH_KEY_IS_STRING != key_type) {
                if (Z_TYPE_P(value) == IS_STRING) {
                    char column[MAX_TABLE_SIZE] = {0};
                    column_quote(Z_STRVAL_P(value), column);
                    sw_multi_memcpy_auto_realloc(order_condition, 2, column, ",");
                }
            } else {
                if (Z_TYPE_P(value) == IS_STRING && (strcmp(Z_STRVAL_P(value), "ASC") == 0 || strcmp(Z_STRVAL_P(value), "DESC") == 0)) {
                    char column[MAX_TABLE_SIZE] = {0};
                    column_quote(key, column);
                    sw_multi_memcpy_auto_realloc(order_condition, 3, column, Z_STRVAL_P(value), ",");
                }
            }

            if (key_len == 0) {}

            SW_HASHTABLE_FOREACH_END();
            char tmp[2] = ",";
            rtrim_str(*order_condition, tmp);
        }
    }
    return *order_condition;
}

//limit
char* limit_implode(zval* limit, char** limit_condition) 
{
    if (!SW_IS_EMPTY(limit)) {
        if (Z_TYPE_P(limit) == IS_STRING || Z_TYPE_P(limit) == IS_LONG) {
            convert_to_string(limit);
            if (is_numeric_string(Z_STRVAL_P(limit), Z_STRLEN_P(limit), NULL, NULL, 0)) {
                sw_multi_memcpy_auto_realloc(limit_condition, 1, Z_STRVAL_P(limit));
            }
        } else if (Z_TYPE_P(limit) == IS_ARRAY) {
            zval* offset_val = zend_hash_index_find(Z_ARRVAL_P(limit), 0);
            zval* limit_val = zend_hash_index_find(Z_ARRVAL_P(limit), 1);
            convert_to_string(limit_val);
            convert_to_string(offset_val);

            if (is_numeric_string(Z_STRVAL_P(limit_val), Z_STRLEN_P(limit_val), NULL, NULL, 0)
                    && is_numeric_string(Z_STRVAL_P(offset_val), Z_STRLEN_P(offset_val), NULL, NULL, 0)) {
                sw_multi_memcpy_auto_realloc(limit_condition, 3, Z_STRVAL_P(limit_val), " OFFSET ", Z_STRVAL_P(offset_val));
            }
        }
    }

    return *limit_condition;
}

static char* where_clause(zval* where, zval* map, char** sql) 
{
    if (SW_IS_EMPTY(where)) {
        return *sql;
    }

    char* group_by_condition = NULL;
    char* having_condition = NULL;
    char* order_condition = NULL;
    char* limit_condition = NULL;

    char* where_condition = NULL;
    sw_string_malloc_32(&where_condition, 0);

    if (SW_IS_ARRAY(where)) {
        char * key;
        zval *value;
        uint32_t key_len;
        int key_type;

        char op_tmp[10] = "AND";

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(where), key, key_len, key_type, value)
        if (HASH_KEY_IS_STRING != key_type) {
            continue;
        } else {
            if (strcmp(key, "GROUP") == 0) {
                sw_string_malloc_32(&group_by_condition, 0);
                group_by_implode(value, &group_by_condition);
            } else if (strcmp(key, "HAVING") == 0) {
                sw_string_malloc_32(&having_condition, 0);
                having_implode(value, map, &having_condition);
            } else if (strcmp(key, "ORDER") == 0) {
                sw_string_malloc_32(&order_condition, 0);
                order_implode(value, &order_condition);
            } else if (strcmp(key, "LIMIT") == 0) {
                sw_string_malloc_32(&limit_condition, 0);
                limit_implode(value, &limit_condition);
            } else { // where clause
                where_implode(key, value, map, &where_condition, op_tmp);
            }
        }

        if (key_len == 0) {}

        SW_HASHTABLE_FOREACH_END();

        strreplace(where_condition, "( AND", "(");
        trim(ltrim_str(ltrim(where_condition), op_tmp));
        if (where_condition[0] != '\0') {
            sw_multi_memcpy_auto_realloc(sql, 2, " WHERE ", where_condition);
        }
    }

    sw_string_free_32(where_condition);

    if (group_by_condition != NULL) {
        sw_multi_memcpy_auto_realloc(sql, 2, " GROUP BY ", group_by_condition);
        sw_string_free_32(group_by_condition);
    }

    if (having_condition != NULL) {
        sw_multi_memcpy_auto_realloc(sql, 2, " HAVING ", having_condition);
        sw_string_free_32(having_condition);
    }

    if (order_condition != NULL) {
        sw_multi_memcpy_auto_realloc(sql, 2, " ORDER BY ", order_condition);
        sw_string_free_32(order_condition);
    }

    if (limit_condition != NULL) {
        sw_multi_memcpy_auto_realloc(sql, 2, " LIMIT ", limit_condition);
        sw_string_free_32(limit_condition);
    }

    return *sql;
}

static char* select_context(char* table, zval* map, zval* join, zval* columns, zval* where, char** sql) 
{
    char* table_query;
    sw_string_malloc_32(&table_query, 0);

    char table_match[MAX_TABLE_SIZE] = {0};
    char alias_match[MAX_TABLE_SIZE] = {0};

    preg_table_match(table, table_match, alias_match);
    if (!sw_is_string_empty(table_match) && !sw_is_string_empty(alias_match)) {
        sw_multi_memcpy_auto_realloc(&table_query, 5, "`", table_match, "` AS `", alias_match, "`");
    } else {
        sw_multi_memcpy_auto_realloc(&table_query, 3, "`", table, "`");
    }

    char* first_join_key = NULL;
    zval* real_where = where;
    zval* real_columns = columns;

    if (SW_IS_ARRAY(join) && (first_join_key = sw_get_array_key_index(join, 0)) != NULL && sw_strpos(first_join_key, "[") == 0) {
        if (sw_is_string_empty(alias_match)) {
            handle_join(join, table, &table_query);
        } else {
            handle_join(join, alias_match, &table_query);
        }
    } else {
        if (SW_IS_NULL(where)) {
            real_columns = join;
            real_where = columns;
        }
    }

    char* column_query;
    sw_string_malloc_32(&column_query, 0);

    column_push(real_columns, map, &column_query);

    sw_multi_memcpy_auto_realloc(sql, 4, "SELECT ", column_query, " FROM ", table_query);

    sw_string_free_32(column_query);
    sw_string_free_32(table_query);

    where_clause(real_where, map, sql);
    return *sql;
}

static PHP_METHOD(swoole_mysql_coro, select) 
{
    char* table = NULL;
    size_t table_len;
    zval* join = NULL, *columns = NULL, *where = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz|zz", &table, &table_len, &join, &columns, &where) == FAILURE) {
        RETURN_FALSE;
    }

    char *sql;
    zval *map;

    SW_MAKE_STD_ZVAL(map);
    array_init(map);

    sw_string_malloc_32(&sql, 0);

    select_context(table, map, join, columns, where, &sql);

    zval *ret_val = NULL, *z_sql = NULL;
    SW_MAKE_STD_ZVAL(ret_val);
    array_init(ret_val);

    SW_MAKE_STD_ZVAL(z_sql);
    ZVAL_STRING(z_sql, sql);
    sw_string_free_32(sql);

    add_assoc_zval(ret_val, "sql", z_sql);
    add_assoc_zval(ret_val, "bind_value", map);

    RETVAL_ZVAL(ret_val, 1, 1);
}

PHP_METHOD(swoole_mysql_coro, insert) 
{
    char *table = NULL;
    size_t table_len;
    zval *data = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &table, &table_len, &data) == FAILURE) {
        RETURN_FALSE;
    }

    char *insert_sql, *insert_keys,*insert_value;
    char *key;
    zval *value;
    uint32_t key_len;
    int key_type;
    char longval[MAP_ITOA_INT_SIZE], doubleval[32];

    sw_string_malloc_32(&insert_sql, 0);
    sw_string_malloc_32(&insert_keys, 0);
    sw_string_malloc_32(&insert_value, 0);

    SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(data), key, key_len, key_type, value)
    if (HASH_KEY_IS_STRING != key_type) {
        sw_string_free_32(insert_keys);
        sw_string_free_32(insert_value);
        sw_string_free_32(insert_sql);
        swoole_php_fatal_error(E_WARNING, "input data must be key/value hash, not index array.");
        RETURN_FALSE;
    } else {
        sw_multi_memcpy_auto_realloc(&insert_keys, 3, "`", key, "`,");

        switch (Z_TYPE_P(value)) {
        case IS_NULL:
            sw_multi_memcpy_auto_realloc(&insert_value, 1, "NULL,");
            break;
        case IS_ARRAY:
            sw_multi_memcpy_auto_realloc(&insert_value, 1, "ARRAY,");
            break;
        case IS_TRUE:
            sw_multi_memcpy_auto_realloc(&insert_value, 1, "1,");
            break;
        case IS_FALSE:
            sw_multi_memcpy_auto_realloc(&insert_value, 1, "0,");
            break;
        case IS_LONG:
            sw_itoa(Z_LVAL_P(value), longval);
            sw_multi_memcpy_auto_realloc(&insert_value, 2, longval, ",");
            break;
        case IS_DOUBLE:
            sprintf(doubleval, "%g", Z_DVAL_P(value));
            sw_multi_memcpy_auto_realloc(&insert_value, 2, doubleval, ",");
            break;
        case IS_STRING:
            sw_multi_memcpy_auto_realloc(&insert_value, 3, "'", Z_STRVAL_P(value), "',");
            break;
        }
    }

    if (key_len == 0) {}
    SW_HASHTABLE_FOREACH_END();

    char tmp[2] = ",";
    rtrim_str(insert_keys, tmp);
    rtrim_str(insert_value, tmp);

    sw_multi_memcpy_auto_realloc(&insert_sql, 7, "INSERT INTO `", table, "` (", insert_keys ,") values (", insert_value, ")");
    sw_string_free_32(insert_keys);
    sw_string_free_32(insert_value);

    zval *ret_val = NULL, *z_sql = NULL;
    SW_MAKE_STD_ZVAL(ret_val);
    array_init(ret_val);

    SW_MAKE_STD_ZVAL(z_sql);
    ZVAL_STRING(z_sql, insert_sql);
    sw_string_free_32(insert_sql);

    add_assoc_zval(ret_val, "sql", z_sql);
    RETVAL_ZVAL(ret_val, 1, 1);
}

PHP_METHOD(swoole_mysql_coro, replace) 
{
    char *table = NULL;
    size_t table_len;
    zval *data = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &table, &table_len, &data) == FAILURE) {
        RETURN_FALSE;
    }

    char *replace_sql, *replace_keys,*replace_value;
    char *key;
    zval *value;
    uint32_t key_len;
    int key_type;
    char longval[MAP_ITOA_INT_SIZE], doubleval[32];

    sw_string_malloc_32(&replace_sql, 0);
    sw_string_malloc_32(&replace_keys, 0);
    sw_string_malloc_32(&replace_value, 0);

    SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(data), key, key_len, key_type, value)
    if (HASH_KEY_IS_STRING != key_type) {
        sw_string_free_32(replace_keys);
        sw_string_free_32(replace_value);
        sw_string_free_32(replace_sql);
        swoole_php_fatal_error(E_WARNING, "input data must be key/value hash, not index array.");
        RETURN_FALSE;
    } else {
        sw_multi_memcpy_auto_realloc(&replace_keys, 3, "`", key, "`,");

        switch (Z_TYPE_P(value)) {
        case IS_NULL:
            sw_multi_memcpy_auto_realloc(&replace_value, 1, "NULL,");
            break;
        case IS_ARRAY:
            sw_multi_memcpy_auto_realloc(&replace_value, 1, "ARRAY,");
            break;
        case IS_TRUE:
            sw_multi_memcpy_auto_realloc(&replace_value, 1, "1,");
            break;
        case IS_FALSE:
            sw_multi_memcpy_auto_realloc(&replace_value, 1, "0,");
            break;
        case IS_LONG:
            sw_itoa(Z_LVAL_P(value), longval);
            sw_multi_memcpy_auto_realloc(&replace_value, 2, longval, ",");
            break;
        case IS_DOUBLE:
            sprintf(doubleval, "%g", Z_DVAL_P(value));
            sw_multi_memcpy_auto_realloc(&replace_value, 2, doubleval, ",");
            break;
        case IS_STRING:
            sw_multi_memcpy_auto_realloc(&replace_value, 3, "'", Z_STRVAL_P(value), "',");
            break;
        }

    }

    if (key_len == 0) {}
    SW_HASHTABLE_FOREACH_END();

    char tmp[2] = ",";
    rtrim_str(replace_keys, tmp);
    rtrim_str(replace_value, tmp);
    sw_multi_memcpy_auto_realloc(&replace_sql, 7, "REPLACE INTO `", table, "` (", replace_keys ,") values (", replace_value, ")");
    sw_string_free_32(replace_keys);
    sw_string_free_32(replace_value);

    zval *ret_val = NULL, *z_sql = NULL;
    SW_MAKE_STD_ZVAL(ret_val);
    array_init(ret_val);

    SW_MAKE_STD_ZVAL(z_sql);
    ZVAL_STRING(z_sql, replace_sql);
    sw_string_free_32(replace_sql);

    add_assoc_zval(ret_val, "sql", z_sql);
    RETVAL_ZVAL(ret_val, 1, 1);
}

PHP_METHOD(swoole_mysql_coro, update) 
{
    char *table = NULL;
    size_t table_len;
    zval *data = NULL, *where = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz|z", &table, &table_len, &data, &where) == FAILURE) {
        RETURN_FALSE;
    }

    char *update_sql;
    sw_string_malloc_32(&update_sql, 0);

    char *update_datas;
    char *key;
    zval *value;
    uint32_t key_len;
    int key_type;
    char longval[MAP_ITOA_INT_SIZE], doubleval[32];

    sw_string_malloc_32(&update_datas, 0);

    SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(data), key, key_len, key_type, value)
    if (HASH_KEY_IS_STRING != key_type) {
        sw_string_free_32(update_datas);
        sw_string_free_32(update_sql);
        swoole_php_fatal_error(E_WARNING, "input data must be key/value hash, not index array.");
        RETURN_FALSE;
    } else {
        sw_multi_memcpy_auto_realloc(&update_datas, 3, "`", key, "` = ");

        switch (Z_TYPE_P(value)) {
        case IS_NULL:
            sw_multi_memcpy_auto_realloc(&update_datas, 1, "NULL,");
            break;
        case IS_ARRAY:
            sw_multi_memcpy_auto_realloc(&update_datas, 1, "ARRAY,");
            break;
        case IS_TRUE:
            sw_multi_memcpy_auto_realloc(&update_datas, 1, "1,");
            break;
        case IS_FALSE:
            sw_multi_memcpy_auto_realloc(&update_datas, 1, "0,");
            break;
        case IS_LONG:
            sw_itoa(Z_LVAL_P(value), longval);
            sw_multi_memcpy_auto_realloc(&update_datas, 2, longval, ",");
            break;
        case IS_DOUBLE:
            sprintf(doubleval, "%g", Z_DVAL_P(value));
            sw_multi_memcpy_auto_realloc(&update_datas, 2, doubleval, ",");
            break;
        case IS_STRING:
            sw_multi_memcpy_auto_realloc(&update_datas, 3, "'", Z_STRVAL_P(value), "',");
            break;
        }

    }

    if (key_len == 0) {}

    SW_HASHTABLE_FOREACH_END();

    char tmp[2] = ",";
    rtrim_str(update_datas, tmp);
    sw_multi_memcpy_auto_realloc(&update_sql, 4, "UPDATE `", table, "` SET ", update_datas);
    sw_string_free_32(update_datas);

    zval *map;
    SW_MAKE_STD_ZVAL(map);
    array_init(map);

    where_clause(where, map, & update_sql);

    zval *ret_val = NULL, *z_sql = NULL;
    SW_MAKE_STD_ZVAL(ret_val);
    array_init(ret_val);

    SW_MAKE_STD_ZVAL(z_sql);
    ZVAL_STRING(z_sql, update_sql);
    sw_string_free_32(update_sql);

    add_assoc_zval(ret_val, "sql", z_sql);
    add_assoc_zval(ret_val, "bind_value", map);
    RETVAL_ZVAL(ret_val, 1, 1);
}

PHP_METHOD(swoole_mysql_coro, delete) 
{
    char *table = NULL;
    size_t table_len;
    zval *where = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|z", &table, &table_len, &where) == FAILURE) {
        RETURN_FALSE;
    }

    char *delete_sql;
    sw_string_malloc_32(&delete_sql, 0);
    sw_multi_memcpy_auto_realloc(&delete_sql, 3, "DELETE FROM `", table, "` ");

    zval *map;
    SW_MAKE_STD_ZVAL(map);
    array_init(map);

    where_clause(where, map, & delete_sql);

    zval *ret_val = NULL, *z_sql = NULL;
    SW_MAKE_STD_ZVAL(ret_val);
    array_init(ret_val);

    SW_MAKE_STD_ZVAL(z_sql);
    ZVAL_STRING(z_sql, delete_sql);
    sw_string_free_32(delete_sql);

    add_assoc_zval(ret_val, "sql", z_sql);
    add_assoc_zval(ret_val, "bind_value", map);
    RETVAL_ZVAL(ret_val, 1, 1);
}

static PHP_METHOD(swoole_mysql_coro, recv)
{
    mysql_client *client = (mysql_client *) swoole_get_object(getThis());

    if (!client->defer)
    {
        swoole_php_fatal_error(E_WARNING, "you should not use recv without defer ");
        RETURN_FALSE;
    }

    PHPCoroutine::check_bind("mysql client", client->cid);

    if (client->iowait == SW_MYSQL_CORO_STATUS_DONE)
    {
        client->iowait = SW_MYSQL_CORO_STATUS_READY;
        zval _result = *client->result;
        efree(client->result);
        zval *result = &_result;
        client->result = NULL;
        RETURN_ZVAL(result, 0, 1);
    }

    if (client->iowait != SW_MYSQL_CORO_STATUS_WAIT)
    {
        swoole_php_fatal_error(E_WARNING, "no request");
        RETURN_FALSE;
    }

    client->suspending = 1;
    client->cid = PHPCoroutine::get_cid();
    php_coro_context *context = (php_coro_context *) swoole_get_property(getThis(), 0);
    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_mysql_coro, prepare)
{
    swString sql;
    bzero(&sql, sizeof(sql));

    mysql_client *client = (mysql_client *) swoole_get_object(getThis());
    if (!client || client->state == SW_MYSQL_STATE_CLOSED)
    {
        SwooleG.error = SW_ERROR_CLIENT_NO_CONNECTION;
        zend_update_property_long(swoole_mysql_coro_ce, getThis(), ZEND_STRL("errCode"), SwooleG.error);
        swoole_php_fatal_error(E_WARNING, "The MySQL connection is not established");
        RETURN_FALSE;
    }

    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query");
        RETURN_FALSE;
    }

    PHPCoroutine::check_bind("mysql client", client->cid);

    double timeout = Socket::default_read_timeout;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|d", &sql.str, &sql.length, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (sql.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty");
        RETURN_FALSE;
    }

    if (client->buffer)
    {
        swString_clear(client->buffer);
    }

    client->cmd = SW_MYSQL_COM_STMT_PREPARE;
    client->state = SW_MYSQL_STATE_READ_START;

    if (mysql_prepare_pack(&sql, mysql_request_buffer) < 0)
    {
        RETURN_FALSE;
    }
    //send prepare command
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zval *zobject = getThis();
            zend_update_property_bool(swoole_mysql_coro_ce, zobject, ZEND_STRL("connected"), 0);
            zend_update_property_long(swoole_mysql_coro_ce, zobject, ZEND_STRL("errno"), 2013);
            zend_update_property_string(swoole_mysql_coro_ce, zobject, ZEND_STRL("error"), "Lost connection to MySQL server during query");
        }
        RETURN_FALSE;
    }

    if (client->defer)
    {
        client->iowait = SW_MYSQL_CORO_STATUS_WAIT;
        RETURN_TRUE;
    }

    php_coro_context *context = (php_coro_context *) swoole_get_property(getThis(), 0);
    if (timeout > 0)
    {
        client->timer = swTimer_add(&SwooleG.timer, (long) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
    }
    client->suspending = 1;
    client->cid = PHPCoroutine::get_cid();
    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_mysql_coro_statement, execute)
{
    zval *params = NULL;

    mysql_statement *stmt = (mysql_statement *) swoole_get_object(getThis());
    if (!stmt)
    {
        RETURN_FALSE;
    }

    mysql_client *client = stmt->client;
    if (!client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed", client->fd);
        RETURN_FALSE;
    }

    double timeout = Socket::default_read_timeout;

    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY_EX(params, 1, 0)
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (stmt->buffer)
    {
        swString_clear(stmt->buffer);
    }

    if (swoole_mysql_coro_execute(getThis(), client, params) < 0)
    {
        RETURN_FALSE;
    }

    php_coro_context *context = (php_coro_context *) swoole_get_property(client->object, 0);
    if (timeout > 0)
    {
        client->timer = swTimer_add(&SwooleG.timer, (long) (timeout * 1000), 0, context, swoole_mysql_coro_onTimeout);
        if (client->timer && client->defer)
        {
            context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
        }
    }
    if (client->defer)
    {
        client->iowait = SW_MYSQL_CORO_STATUS_WAIT;
        RETURN_TRUE;
    }
    client->suspending = 1;
    client->cid = PHPCoroutine::get_cid();
    PHPCoroutine::yield_m(return_value, context);
}

static PHP_METHOD(swoole_mysql_coro_statement, fetch)
{
    mysql_statement *stmt = (mysql_statement *) swoole_get_object(getThis());
    if (!stmt)
    {
        RETURN_FALSE;
    }

    if (!stmt->client->connector.fetch_mode)
    {
        RETURN_FALSE;
    }

    if (stmt->result)
    {
        zval args[1];
        // the function argument is a reference
        ZVAL_NEW_REF(stmt->result, stmt->result);
        args[0] = *stmt->result;

        zval fcn;
        ZVAL_STRING(&fcn, "array_shift");
        int ret;
        zval retval;
        ret = call_user_function_ex(EG(function_table), NULL, &fcn, &retval, 1, args, 0, NULL);
        zval_ptr_dtor(&fcn);
        ZVAL_UNREF(stmt->result);

        if (ret == FAILURE)
        {
            if (stmt->result)
            {
                sw_zval_free(stmt->result);
                stmt->result = NULL;
            }
            RETURN_NULL();
        }
        else
        {
            if (php_swoole_array_length(stmt->result) == 0)
            {
                sw_zval_free(stmt->result);
                stmt->result = NULL;
            }
            RETURN_ZVAL(&retval, 0, 1);
        }
    }
    else
    {
        RETURN_NULL();
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, fetchAll)
{
    mysql_statement *stmt = (mysql_statement *) swoole_get_object(getThis());
    if (!stmt)
    {
        RETURN_FALSE;
    }

    if (!stmt->client->connector.fetch_mode)
    {
        RETURN_FALSE;
    }

    if (stmt->result)
    {
        zval _result = *stmt->result;
        efree(stmt->result);
        zval *result = &_result;
        stmt->result = NULL;
        RETURN_ZVAL(result, 0, 1);
    }
    else
    {
        RETURN_NULL();
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, nextResult)
{
    mysql_statement *stmt = (mysql_statement *) swoole_get_object(getThis());
    if (!stmt)
    {
        RETURN_FALSE;
    }

    mysql_client *client = stmt->client;

    if (stmt->buffer && (size_t) stmt->buffer->offset < stmt->buffer->length)
    {
        client->cmd = SW_MYSQL_COM_STMT_EXECUTE;
        client->state = SW_MYSQL_STATE_READ_START;
        client->statement = stmt;
        zval *result = NULL;
        if (swoole_mysql_coro_parse_response(client, &result, 1) == SW_OK)
        {
            swoole_mysql_coro_parse_end(client, stmt->buffer); // ending tidy up

            zval _result = *result;
            efree(result);
            result = &_result;
            RETURN_ZVAL(result, 0, 1);
        }
        else
        {
            RETURN_FALSE;
        }
    }
    else
    {
        RETURN_NULL();
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, __destruct)
{
    SW_PREVENT_USER_DESTRUCT();

    mysql_statement *stmt = (mysql_statement *) swoole_get_object(getThis());
    if (!stmt)
    {
        return;
    }
    swoole_mysql_coro_statement_close(stmt);
    swoole_mysql_coro_statement_free(stmt);
    swLinkedList_remove(stmt->client->statement_list, stmt);
    efree(stmt);
}

#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql_coro, escape)
{
    swString str;
    bzero(&str, sizeof(str));
    zend_long flags = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|l", &str.str, &str.length, &flags) == FAILURE)
    {
        RETURN_FALSE;
    }

    mysql_client *client = (mysql_client *) swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql");
        RETURN_FALSE;
    }
    if (!client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed", client->fd);
        RETURN_FALSE;
    }

    char *newstr = (char *) safe_emalloc(2, str.length + 1, 1);
    if (newstr == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "emalloc(%ld) failed", str.length + 1);
        RETURN_FALSE;
    }

    const MYSQLND_CHARSET* cset = mysqlnd_find_charset_nr(client->connector.character_set);
    if (cset == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "unknown mysql charset[%d]", client->connector.character_set);
        RETURN_FALSE;
    }
    int newstr_len = mysqlnd_cset_escape_slashes(cset, newstr, str.str, str.length);
    if (newstr_len < 0)
    {
        swoole_php_fatal_error(E_ERROR, "mysqlnd_cset_escape_slashes() failed");
        RETURN_FALSE;
    }
    RETVAL_STRINGL(newstr, newstr_len);
    efree(newstr);
    return;
}
#endif

static PHP_METHOD(swoole_mysql_coro, close)
{
    if (swoole_mysql_coro_close(getThis()) == FAILURE)
    {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static void swoole_mysql_coro_free_object(zend_object *object)
{
    // as __destruct
    uint32_t handle = object->handle;
    zval _zobject, *zobject = &_zobject;
    ZVAL_OBJ(zobject, object);

    mysql_client *client = (mysql_client *) swoole_get_object_by_handle(handle);
    if (client)
    {
        if (client->state != SW_MYSQL_STATE_CLOSED && client->cli)
        {
            swoole_mysql_coro_close(zobject);
        }
        if (client->buffer)
        {
            swString_free(client->buffer);
        }
        efree(client);
        swoole_set_object_by_handle(handle, NULL);
    }

    php_coro_context *context = (php_coro_context *) swoole_get_property_by_handle(handle, 0);
    if (context)
    {
        efree(context);
        swoole_set_property_by_handle(handle, 0, NULL);
    }

    zend_object_std_dtor(object);
}

static int swoole_mysql_coro_onError(swReactor *reactor, swEvent *event)
{
    zval *retval = NULL, *result = sw_malloc_zval();;
    mysql_client *client = (mysql_client *) event->socket->object;
    zval *zobject = client->object;

    swoole_mysql_coro_close(zobject);

    zend_update_property_string(swoole_mysql_coro_ce, zobject, ZEND_STRL("connect_error"), "EPOLLERR/EPOLLHUP/EPOLLRDHUP happen!");
    zend_update_property_long(swoole_mysql_coro_ce, zobject, ZEND_STRL("connect_errno"), ECONNRESET);
    ZVAL_BOOL(result, 0);
    if (client->defer && !client->suspending)
    {
        client->result = result;
        return SW_OK;
    }
    client->suspending = 0;
    client->cid = 0;
    php_coro_context *sw_current_context = (php_coro_context *) swoole_get_property(zobject, 0);
    int ret = PHPCoroutine::resume_m(sw_current_context, result, retval);
    sw_zval_free(result);

    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }

    return SW_OK;
}

static void swoole_mysql_coro_onConnect(mysql_client *client)
{
    zval *zobject = client->object;

    zval *retval = NULL;
    zval result;

    if (client->connector.timer)
    {
        swTimer_del(&SwooleG.timer, client->connector.timer);
        client->connector.timer = NULL;
    }

    //SwooleG.main_reactor->del(SwooleG.main_reactor, client->fd);

    if (client->connector.error_code > 0)
    {
        zend_update_property_stringl(swoole_mysql_coro_ce, zobject, ZEND_STRL("connect_error"), client->connector.error_msg, client->connector.error_length);
        zend_update_property_long(swoole_mysql_coro_ce, zobject, ZEND_STRL("connect_errno"), client->connector.error_code);

        ZVAL_BOOL(&result, 0);

        swoole_mysql_coro_close(zobject);
    }
    else
    {
        client->state = SW_MYSQL_STATE_QUERY;
        client->iowait = SW_MYSQL_CORO_STATUS_READY;
        zend_update_property_bool(swoole_mysql_coro_ce, zobject, ZEND_STRL("connected"), 1);
        client->connected = 1;
        ZVAL_BOOL(&result, 1);
    }

    client->cid = 0;

    php_coro_context *sw_current_context = (php_coro_context *) swoole_get_property(zobject, 0);
    int ret = PHPCoroutine::resume_m(sw_current_context, &result, retval);
    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }
}

static void swoole_mysql_coro_onConnectTimeout(swTimer *timer, swTimer_node *tnode)
{
    zval *result = sw_malloc_zval();;
    zval *retval = NULL;
    php_coro_context *ctx = (php_coro_context *) tnode->data;
    zval _zobject = ctx->coro_params;
    zval *zobject = & _zobject;

    ZVAL_BOOL(result, 0);

    mysql_client *client = (mysql_client *) swoole_get_object(zobject);

    zend_update_property_string(swoole_mysql_coro_ce, zobject, ZEND_STRL("connect_error"), "connect timeout");
    zend_update_property_long(swoole_mysql_coro_ce, zobject, ZEND_STRL("connect_errno"), ETIMEDOUT);

    //timeout close conncttion
    client->connector.timer = NULL;
    swoole_mysql_coro_close(zobject);

    if (client->defer && !client->suspending)
    {
        client->result = result;
        return;
    }
    client->suspending = 0;
    client->cid = 0;

    int ret = PHPCoroutine::resume_m(ctx, result, retval);

    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }

    sw_zval_free(result);
}

static void swoole_mysql_coro_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    zval *result = sw_malloc_zval();;
    zval *retval = NULL;
    php_coro_context *ctx = (php_coro_context *) tnode->data;
    zval _zobject = ctx->coro_params;
    zval *zobject = & _zobject;

    ZVAL_BOOL(result, 0);

    mysql_client *client = (mysql_client *) swoole_get_object(zobject);

    zend_update_property_string(swoole_mysql_coro_ce, zobject, ZEND_STRL("error"), "query timeout");
    zend_update_property_long(swoole_mysql_coro_ce, zobject, ZEND_STRL("errno"), ETIMEDOUT);

    //timeout close conncttion
    client->timer = NULL;
    client->state = SW_MYSQL_STATE_QUERY;
    swoole_mysql_coro_close(zobject);

    if (client->defer && !client->suspending)
    {
        client->result = result;
        return;
    }
    client->suspending = 0;
    client->cid = 0;

    int ret = PHPCoroutine::resume_m(ctx, result, retval);

    if (ret == SW_CORO_ERR_END && retval)
    {
        zval_ptr_dtor(retval);
    }

    sw_zval_free(result);
}

static int swoole_mysql_coro_onWrite(swReactor *reactor, swEvent *event)
{
    if (event->socket->active)
    {
        return swReactor_onWrite(SwooleG.main_reactor, event);
    }

    socklen_t len = sizeof(SwooleG.error);
    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &SwooleG.error, &len) < 0)
    {
        swSysWarn("getsockopt(%d) failed", event->fd);
        return SW_ERR;
    }

    mysql_client *client = (mysql_client *) event->socket->object;
    //success
    if (SwooleG.error == 0)
    {
        //listen read event
        SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, PHP_SWOOLE_FD_MYSQL_CORO | SW_EVENT_READ);
        //connected
        event->socket->active = 1;
        client->connector.error_code = 0;
        client->connector.error_msg = (char *) "";
        client->connector.error_length = 0;
        client->handshake = SW_MYSQL_HANDSHAKE_WAIT_REQUEST;
    }
    else
    {
        client->connector.error_code = SwooleG.error;
        client->connector.error_msg = strerror(SwooleG.error);
        client->connector.error_length = strlen(client->connector.error_msg);
        swoole_mysql_coro_onConnect(client);
    }
    return SW_OK;
}

static int swoole_mysql_coro_onHandShake(mysql_client *client)
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
            swSysWarn("Read from socket[%d] failed", cli->socket->fd);
            return SW_ERR;
        case SW_CLOSE:
            _system_call_error:
            connector->error_code = errno;
            connector->error_msg = strerror(errno);
            connector->error_length = strlen(connector->error_msg);
            swoole_mysql_coro_onConnect(client);
            return SW_OK;
        case SW_WAIT:
            return SW_OK;
        default:
            return SW_ERR;
        }
    }
    else if (n == 0)
    {
        errno = ECONNRESET;
        goto _system_call_error;
    }

    buffer->length += n;

    int ret = 0;

    _again:
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "handshake on %d", client->handshake);
    if (client->switch_check)
    {
        // after handshake we need check if server request us to switch auth type first
        goto _check_switch;
    }

    switch(client->handshake)
    {
    case SW_MYSQL_HANDSHAKE_WAIT_REQUEST:
    {
        client->switch_check = 1;
        ret = mysql_handshake(connector, buffer->str, buffer->length);

        if (ret < 0)
        {
            goto _error;
        }
        else if (ret > 0)
        {
            _send:
            if (cli->send(cli, connector->buf, connector->packet_length + 4, 0) < 0)
            {
                goto _system_call_error;
            }
            else
            {
                // clear for the new packet
                swString_clear(buffer);
                // mysql_handshake will return the next state flag
                client->handshake = ret;
            }
        }
        break;
    }
    case SW_MYSQL_HANDSHAKE_WAIT_SWITCH:
    {
        _check_switch:
        client->switch_check = 0;
        int next_state;
        // handle auth switch request
        switch (next_state = mysql_auth_switch(connector, buffer->str, buffer->length))
        {
        case SW_AGAIN:
            return SW_OK;
        case SW_ERR:
            // not the switch packet, go to the next
            goto _again;
        default:
            ret = next_state;
            goto _send;
        }
        break;
    }
    case SW_MYSQL_HANDSHAKE_WAIT_SIGNATURE:
    {
        switch (mysql_parse_auth_signature(buffer, connector))
        {
        case SW_MYSQL_AUTH_SIGNATURE_SUCCESS:
        {
            client->handshake = SW_MYSQL_HANDSHAKE_WAIT_RESULT;
            break;
        }
        case SW_MYSQL_AUTH_SIGNATURE_FULL_AUTH_REQUIRED:
        {
            // send response and wait RSA public key
            ret = SW_MYSQL_HANDSHAKE_WAIT_RSA; // handshake = ret
            goto _send;
        }
        default:
        {
            goto _error;
        }
        }

        // may be more packets
        if ((size_t) buffer->offset < buffer->length)
        {
            goto _again;
        }
        else
        {
            swString_clear(buffer);
        }
        break;
    }
    case SW_MYSQL_HANDSHAKE_WAIT_RSA:
    {
        // encode by RSA
#ifdef SW_MYSQL_RSA_SUPPORT
        switch (mysql_parse_rsa(connector, SW_STRINGCVL(buffer)))
        {
        case SW_AGAIN:
            return SW_OK;
        case SW_OK:
            ret = SW_MYSQL_HANDSHAKE_WAIT_RESULT; // handshake = ret
            goto _send;
        default:
            goto _error;
        }
#else
        connector->error_code = -1;
        connector->error_msg = (char *) "MySQL8 RSA-Auth need enable OpenSSL!";
        connector->error_length = strlen(connector->error_msg);
        swoole_mysql_coro_onConnect(client);
        return SW_OK;
#endif
        break;
    }
    default:
    {
        ret = mysql_get_result(connector, SW_STRINGCVL(buffer));
        if (ret < 0)
        {
            _error:
            swoole_mysql_coro_onConnect(client);
        }
        else if (ret > 0)
        {
            swString_clear(buffer);
            client->handshake = SW_MYSQL_HANDSHAKE_COMPLETED;
            swoole_mysql_coro_onConnect(client);
        }
        // else recv again
    }
    }

    return SW_OK;
}

static int swoole_mysql_coro_onRead(swReactor *reactor, swEvent *event)
{
    mysql_client *client = (mysql_client *) event->socket->object;
    if (client->handshake != SW_MYSQL_HANDSHAKE_COMPLETED)
    {
        return swoole_mysql_coro_onHandShake(client);
    }

    if (client->timer)
    {
        swTimer_del(&SwooleG.timer, client->timer);
        client->timer = NULL;
    }

    int sock = event->fd;
    int ret;

    zval *zobject = client->object;

    swString *buffer;
    if (client->cmd == SW_MYSQL_COM_STMT_EXECUTE)
    {
        if (client->statement->buffer == NULL)
        {
            // statement save the response data itself
            client->statement->buffer = swString_new(SW_BUFFER_SIZE_BIG);
        }
        buffer = client->statement->buffer;
    }
    else
    {
        buffer = client->buffer;
    }

    zval *retval = NULL;
    zval *result = NULL;

    while(1)
    {
        ret = recv(sock, buffer->str + buffer->length, buffer->size - buffer->length, 0);
        swTraceLog(SW_TRACE_MYSQL_CLIENT, "recv-ret=%d, buffer-length=%zu", ret, buffer->length);
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
                    swSysWarn("Read from socket[%d] failed", event->fd);
                    return SW_ERR;
                case SW_CLOSE:
                    goto _close_fd;
                case SW_WAIT:
                    return SW_OK;
                default:
                    return SW_ERR;
                }
            }
        }
        else if (ret == 0)
        {
            _close_fd:
            if (client->state == SW_MYSQL_STATE_READ_END)
            {
                goto _parse_response;
            }


            zend_update_property_long(swoole_mysql_coro_ce, zobject, ZEND_STRL("connect_errno"), 111);
            zend_update_property_string(swoole_mysql_coro_ce, zobject, ZEND_STRL("connect_error"), "connection close by peer");
            if (client->connected)
            {
                client->connected = 0;
                zend_update_property_long(swoole_mysql_coro_ce, zobject, ZEND_STRL("errno"), 2006);
                zend_update_property_string(swoole_mysql_coro_ce, zobject, ZEND_STRL("error"), "MySQL server has gone away");
            }

            _active_close:
            client->state = SW_MYSQL_STATE_QUERY;
            swoole_mysql_coro_close(zobject);

            if (!client->cid)
            {
                return SW_OK;
            }

            result = sw_malloc_zval();
            ZVAL_BOOL(result, 0);
            if (client->defer && !client->suspending)
            {
                client->iowait = SW_MYSQL_CORO_STATUS_DONE;
                client->result = result;
                return SW_OK;
            }
            client->suspending = 0;
            client->cid = 0;

            php_coro_context *sw_current_context = (php_coro_context *) swoole_get_property(zobject, 0);
            ret = PHPCoroutine::resume_m(sw_current_context, result, retval);
            sw_zval_free(result);
            if (ret == SW_CORO_ERR_END && retval)
            {
                zval_ptr_dtor(retval);
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
                    swoole_php_fatal_error(E_ERROR, "malloc failed");
                    reactor->del(SwooleG.main_reactor, event->fd);
                }
                continue;
            }

            _parse_response:

            if (client->tmp_result)
            {
                _check_over:
                // maybe more responses has already received in buffer, we check it now.
                if (mysql_is_over(client) != SW_OK)
                {
                    // the **last** sever status flag shows that more results exist but we hasn't received.
                    return SW_OK;
                }
                else
                {
                    result = client->tmp_result;
                    client->tmp_result = NULL;
                }
            }
            else
            {
                ret = swoole_mysql_coro_parse_response(client, &result, 0);
                if (ret == SW_AGAIN)
                {
                    return SW_OK; // parse error or need again
                }
                if (client->response.status_code & SW_MYSQL_SERVER_MORE_RESULTS_EXISTS)
                {
                    client->tmp_result = result;
                    goto _check_over;
                }
            }
            swoole_mysql_coro_parse_end(client, buffer); // ending tidy up

            if (client->defer && !client->suspending)
            {
                client->iowait = SW_MYSQL_CORO_STATUS_DONE;
                client->result = result;
                return SW_OK;
            }

            if (!client->cid)
            {
                goto _active_close; // error
            }

            client->suspending = 0;
            client->iowait = SW_MYSQL_CORO_STATUS_READY;
            client->cid = 0;

            php_coro_context *sw_current_context = (php_coro_context *) swoole_get_property(zobject, 0);
            ret = PHPCoroutine::resume_m(sw_current_context, result, retval);
            if (result)
            {
                sw_zval_free(result);
            }
            if (ret == SW_CORO_ERR_END && retval)
            {
                zval_ptr_dtor(retval);
            }
            return SW_OK;
        }
    }
    return SW_OK;
}

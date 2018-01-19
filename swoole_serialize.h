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
  | Author: xinhua.guo  <woshiguo35@gmail.com>                        |
  +----------------------------------------------------------------------+
 */

#ifndef SERIALIZE_H
#define	SERIALIZE_H

#ifdef	__cplusplus
extern "C"
{
#endif
#if PHP_MAJOR_VERSION >= 7

#define SERIA_SIZE 4096
#define FILTER_SIZE 1024

typedef struct _seriaString
{
    size_t offset;
    size_t total;
    void * buffer; //zend_string
} seriaString;

typedef struct _SBucketType
{
    zend_uchar key_type : 1;
    zend_uchar key_len : 2;
    zend_uchar data_len : 2;
    zend_uchar data_type : 3; //IS_UNDEF means object now
} SBucketType;

struct _swMinFilter
{
    uint32_t mini_fillter_find_cnt;
    uint32_t mini_fillter_miss_cnt;
    uint32_t bigger_fillter_size;
};

struct _swSeriaG
{
    zval sleep_fname;
    zval weekup_fname;
    zend_uchar pack_string;
    struct _swMinFilter filter;
};

#pragma pack (4)

typedef struct _swPoolstr
{
    zend_string *str;
    uint32_t offset;
} swPoolstr;

#pragma pack ()


static void *unser_start = 0;
static swPoolstr mini_filter[FILTER_SIZE];
static swPoolstr *bigger_filter = NULL;

#define SERIA_SET_ENTRY_TYPE_WITH_MINUS(buffer,type)        swoole_check_size(buffer, 1);\
                                                        *(char*) (buffer->buffer + buffer->offset) = *((char*) & type);\
                                                        buffer->offset += 1;

#define SERIA_SET_ENTRY_SHORT_WITH_MINUS(buffer,data)        swoole_check_size(buffer, 2);\
                                                            *(short*) (buffer->buffer + buffer->offset) = data;\
                                                           buffer->offset += 2;

#define SERIA_SET_ENTRY_SIZE4_WITH_MINUS(buffer,data)        swoole_check_size(buffer, 4);\
                                                            *(int32_t*) (buffer->buffer + buffer->offset) = data;\
                                                            buffer->offset += 4;

#define SERIA_SET_ENTRY_TYPE(buffer,type)        swoole_check_size(buffer, 1);\
                                                 *(zend_uchar*) (buffer->buffer + buffer->offset) = *((zend_uchar*) & type);\
                                                 buffer->offset += 1;

#define SERIA_GET_ENTRY_TYPE(buffer)            *(zend_uchar*) (buffer->buffer + buffer->offset) = *((zend_uchar*) & type);\
                                                 buffer->offset += 1;

#define SERIA_SET_ENTRY_SHORT(buffer,data)        swoole_check_size(buffer, 2);\
                                                  *(unsigned short*) (buffer->buffer + buffer->offset) = data;\
                                                 buffer->offset += 2;

#define SERIA_SET_ENTRY_SIZE4(buffer,data)        swoole_check_size(buffer, 4);\
                                                  *(uint32_t*) (buffer->buffer + buffer->offset) = data;\
                                                 buffer->offset += 4;

#define SERIA_SET_ENTRY_ULONG(buffer,data)         swoole_check_size(buffer, sizeof(zend_ulong));\
                                                  *(zend_ulong *) (buffer->buffer + buffer->offset) = data;\
                                                 buffer->offset += sizeof(zend_ulong);

#define KEY_TYPE_STRING               1
#define KEY_TYPE_INDEX                0

#define SW_FAST_PACK                  1

#define UNSERIALIZE_OBJECT_TO_ARRAY          1
#define UNSERIALIZE_OBJECT_TO_STDCLASS       2

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* SERIALIZE_H */


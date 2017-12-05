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

#include "php_swoole.h"
#include "swoole_serialize.h"
#ifdef __SSE2__
#include <emmintrin.h>
#endif

#if PHP_MAJOR_VERSION >= 7
#define CPINLINE sw_inline

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_serialize_pack, 0, 0, 1)
ZEND_ARG_INFO(0, data)
ZEND_ARG_INFO(0, flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_serialize_unpack, 0, 0, 1)
ZEND_ARG_INFO(0, string)
ZEND_ARG_INFO(0, args)
ZEND_END_ARG_INFO()

static void swoole_serialize_object(seriaString *buffer, zval *zvalue, size_t start);
static void swoole_serialize_arr(seriaString *buffer, zend_array *zvalue);
static void* swoole_unserialize_arr(void *buffer, zval *zvalue, uint32_t num, long flag);
static void* swoole_unserialize_object(void *buffer, zval *return_value, zend_uchar bucket_len, zval *args, long flag);

static PHP_METHOD(swoole_serialize, pack);
static PHP_METHOD(swoole_serialize, unpack);


static const zend_function_entry swoole_serialize_methods[] = {
    PHP_ME(swoole_serialize, pack, arginfo_swoole_serialize_pack, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_serialize, unpack, arginfo_swoole_serialize_unpack, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

zend_class_entry swoole_serialize_ce;
zend_class_entry *swoole_serialize_class_entry_ptr;

#define SWOOLE_SERI_EOF "EOF"

void swoole_serialize_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_serialize_ce, "swoole_serialize", "Swoole\\Serialize", swoole_serialize_methods);
    swoole_serialize_class_entry_ptr = zend_register_internal_class(&swoole_serialize_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_serialize, "Swoole\\Serialize");

    ZVAL_STRING(&swSeriaG.sleep_fname, "__sleep");
    ZVAL_STRING(&swSeriaG.weekup_fname, "__weekup");

    memset(&swSeriaG.filter, 0, sizeof (swSeriaG.filter));
    memset(&mini_filter, 0, sizeof (mini_filter));

    REGISTER_LONG_CONSTANT("SWOOLE_FAST_PACK", SW_FAST_PACK, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("UNSERIALIZE_OBJECT_TO_ARRAY", UNSERIALIZE_OBJECT_TO_ARRAY, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("UNSERIALIZE_OBJECT_TO_STDCLASS", UNSERIALIZE_OBJECT_TO_STDCLASS, CONST_CS | CONST_PERSISTENT);
}

static CPINLINE int swoole_string_new(size_t size, seriaString *str, zend_uchar type)
{
    int total = ZEND_MM_ALIGNED_SIZE(_STR_HEADER_SIZE + size + 1);
    str->total = total;
    //escape the header for later
    str->offset = _STR_HEADER_SIZE;
    //zend string addr
    str->buffer = ecalloc(1, total);
    if (!str->buffer)
    {
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "malloc Error: %s [%d]", strerror(errno), errno);
    }

    SBucketType real_type = {0};
    real_type.data_type = type;
    *(SBucketType*) (str->buffer + str->offset) = real_type;
    str->offset += sizeof (SBucketType);
    return 0;
}

static CPINLINE void swoole_check_size(seriaString *str, size_t len)
{
    int new_size = len + str->offset;
    //    int new_size = len + str->offset + 3 + sizeof (zend_ulong); //space 1 for the type and 2 for key string len or index len and(zend_ulong) for key h
    if (str->total < new_size)
    {//extend it

        new_size = ZEND_MM_ALIGNED_SIZE(new_size + SERIA_SIZE);
        str->buffer = erealloc2(str->buffer, new_size, str->offset);
        if (!str->buffer)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "realloc Error: %s [%d]", strerror(errno), errno);
        }
        str->total = new_size;
    }
}
#ifdef __SSE2__
void CPINLINE swoole_mini_memcpy(void *dst, const void *src, size_t len)
{
    register unsigned char *dd = (unsigned char*) dst + len;
    register const unsigned char *ss = (const unsigned char*) src + len;
    switch (len)
    {
        case 68: *((int*) (dd - 68)) = *((int*) (ss - 68));
        /* no break */
        case 64: *((int*) (dd - 64)) = *((int*) (ss - 64));
        /* no break */
        case 60: *((int*) (dd - 60)) = *((int*) (ss - 60));
        /* no break */
        case 56: *((int*) (dd - 56)) = *((int*) (ss - 56));
        /* no break */
        case 52: *((int*) (dd - 52)) = *((int*) (ss - 52));
        /* no break */
        case 48: *((int*) (dd - 48)) = *((int*) (ss - 48));
        /* no break */
        case 44: *((int*) (dd - 44)) = *((int*) (ss - 44));
        /* no break */
        case 40: *((int*) (dd - 40)) = *((int*) (ss - 40));
        /* no break */
        case 36: *((int*) (dd - 36)) = *((int*) (ss - 36));
        /* no break */
        case 32: *((int*) (dd - 32)) = *((int*) (ss - 32));
        /* no break */
        case 28: *((int*) (dd - 28)) = *((int*) (ss - 28));
        /* no break */
        case 24: *((int*) (dd - 24)) = *((int*) (ss - 24));
        /* no break */
        case 20: *((int*) (dd - 20)) = *((int*) (ss - 20));
        /* no break */
        case 16: *((int*) (dd - 16)) = *((int*) (ss - 16));
        /* no break */
        case 12: *((int*) (dd - 12)) = *((int*) (ss - 12));
        /* no break */
        case 8: *((int*) (dd - 8)) = *((int*) (ss - 8));
        /* no break */
        case 4: *((int*) (dd - 4)) = *((int*) (ss - 4));
            break;
        case 67: *((int*) (dd - 67)) = *((int*) (ss - 67));
        /* no break */
        case 63: *((int*) (dd - 63)) = *((int*) (ss - 63));
        /* no break */
        case 59: *((int*) (dd - 59)) = *((int*) (ss - 59));
        /* no break */
        case 55: *((int*) (dd - 55)) = *((int*) (ss - 55));
        /* no break */
        case 51: *((int*) (dd - 51)) = *((int*) (ss - 51));
        /* no break */
        case 47: *((int*) (dd - 47)) = *((int*) (ss - 47));
        /* no break */
        case 43: *((int*) (dd - 43)) = *((int*) (ss - 43));
        /* no break */
        case 39: *((int*) (dd - 39)) = *((int*) (ss - 39));
        /* no break */
        case 35: *((int*) (dd - 35)) = *((int*) (ss - 35));
        /* no break */
        case 31: *((int*) (dd - 31)) = *((int*) (ss - 31));
        /* no break */
        case 27: *((int*) (dd - 27)) = *((int*) (ss - 27));
        /* no break */
        case 23: *((int*) (dd - 23)) = *((int*) (ss - 23));
        /* no break */
        case 19: *((int*) (dd - 19)) = *((int*) (ss - 19));
        /* no break */
        case 15: *((int*) (dd - 15)) = *((int*) (ss - 15));
        /* no break */
        case 11: *((int*) (dd - 11)) = *((int*) (ss - 11));
        /* no break */
        case 7: *((int*) (dd - 7)) = *((int*) (ss - 7));
            *((int*) (dd - 4)) = *((int*) (ss - 4));
            break;
        case 3: *((short*) (dd - 3)) = *((short*) (ss - 3));
            dd[-1] = ss[-1];
            break;
        case 66: *((int*) (dd - 66)) = *((int*) (ss - 66));
        /* no break */
        case 62: *((int*) (dd - 62)) = *((int*) (ss - 62));
        /* no break */
        case 58: *((int*) (dd - 58)) = *((int*) (ss - 58));
        /* no break */
        case 54: *((int*) (dd - 54)) = *((int*) (ss - 54));
        /* no break */
        case 50: *((int*) (dd - 50)) = *((int*) (ss - 50));
        /* no break */
        case 46: *((int*) (dd - 46)) = *((int*) (ss - 46));
        /* no break */
        case 42: *((int*) (dd - 42)) = *((int*) (ss - 42));
        /* no break */
        case 38: *((int*) (dd - 38)) = *((int*) (ss - 38));
        /* no break */
        case 34: *((int*) (dd - 34)) = *((int*) (ss - 34));
        /* no break */
        case 30: *((int*) (dd - 30)) = *((int*) (ss - 30));
        /* no break */
        case 26: *((int*) (dd - 26)) = *((int*) (ss - 26));
        /* no break */
        case 22: *((int*) (dd - 22)) = *((int*) (ss - 22));
        /* no break */
        case 18: *((int*) (dd - 18)) = *((int*) (ss - 18));
        /* no break */
        case 14: *((int*) (dd - 14)) = *((int*) (ss - 14));
        /* no break */
        case 10: *((int*) (dd - 10)) = *((int*) (ss - 10));
        /* no break */
        case 6: *((int*) (dd - 6)) = *((int*) (ss - 6));
        /* no break */
        case 2: *((short*) (dd - 2)) = *((short*) (ss - 2));
            break;
        case 65: *((int*) (dd - 65)) = *((int*) (ss - 65));
        /* no break */
        case 61: *((int*) (dd - 61)) = *((int*) (ss - 61));
        /* no break */
        case 57: *((int*) (dd - 57)) = *((int*) (ss - 57));
        /* no break */
        case 53: *((int*) (dd - 53)) = *((int*) (ss - 53));
        /* no break */
        case 49: *((int*) (dd - 49)) = *((int*) (ss - 49));
        /* no break */
        case 45: *((int*) (dd - 45)) = *((int*) (ss - 45));
        /* no break */
        case 41: *((int*) (dd - 41)) = *((int*) (ss - 41));
        /* no break */
        case 37: *((int*) (dd - 37)) = *((int*) (ss - 37));
        /* no break */
        case 33: *((int*) (dd - 33)) = *((int*) (ss - 33));
        /* no break */
        case 29: *((int*) (dd - 29)) = *((int*) (ss - 29));
        /* no break */
        case 25: *((int*) (dd - 25)) = *((int*) (ss - 25));
        /* no break */
        case 21: *((int*) (dd - 21)) = *((int*) (ss - 21));
        /* no break */
        case 17: *((int*) (dd - 17)) = *((int*) (ss - 17));
        /* no break */
        case 13: *((int*) (dd - 13)) = *((int*) (ss - 13));
        /* no break */
        case 9: *((int*) (dd - 9)) = *((int*) (ss - 9));
        /* no break */
        case 5: *((int*) (dd - 5)) = *((int*) (ss - 5));
        /* no break */
        case 1: dd[-1] = ss[-1];
            break;
        case 0:
        default: break;
    }
}

void CPINLINE swoole_memcpy_fast(void *destination, const void *source, size_t size)
{
    unsigned char *dst = (unsigned char*) destination;
    const unsigned char *src = (const unsigned char*) source;

    // small memory copy
    if (size < 64)
    {
        swoole_mini_memcpy(dst, src, size);
        return;
    }

    size_t diff = (((size_t) dst + 15L) & (~15L)) - ((size_t) dst);
    if (diff > 0)
    {
        swoole_mini_memcpy(dst, src, diff);
        dst += diff;
        src += diff;
        size -= diff;
    }

    // 4个寄存器
    __m128i c1, c2, c3, c4;

    if ((((size_t) src) & 15L) == 0)
    {
        for(; size >= 64; size -= 64)
        {
            //load 时候将下次要用的数据提前fetch
            _mm_prefetch((const char*) (src + 64), _MM_HINT_NTA);
            _mm_prefetch((const char*) (dst + 64), _MM_HINT_T0);
            //从内存中load到寄存器
            c1 = _mm_load_si128(((const __m128i*) src) + 0);
            c2 = _mm_load_si128(((const __m128i*) src) + 1);
            c3 = _mm_load_si128(((const __m128i*) src) + 2);
            c4 = _mm_load_si128(((const __m128i*) src) + 3);
            src += 64;
            //写回内存
            _mm_store_si128((((__m128i*) dst) + 0), c1);
            _mm_store_si128((((__m128i*) dst) + 1), c2);
            _mm_store_si128((((__m128i*) dst) + 2), c3);
            _mm_store_si128((((__m128i*) dst) + 3), c4);
            dst += 64;
        }
    }
    else
    {
        for(; size >= 64; size -= 64)
        {
            _mm_prefetch((const char*) (src + 64), _MM_HINT_NTA);
            _mm_prefetch((const char*) (dst + 64), _MM_HINT_T0);
            c1 = _mm_loadu_si128(((const __m128i*) src) + 0);
            c2 = _mm_loadu_si128(((const __m128i*) src) + 1);
            c3 = _mm_loadu_si128(((const __m128i*) src) + 2);
            c4 = _mm_loadu_si128(((const __m128i*) src) + 3);
            src += 64;
            _mm_store_si128((((__m128i*) dst) + 0), c1);
            _mm_store_si128((((__m128i*) dst) + 1), c2);
            _mm_store_si128((((__m128i*) dst) + 2), c3);
            _mm_store_si128((((__m128i*) dst) + 3), c4);
            dst += 64;
        }
    }
    // _mm_sfence();

    // return memcpy_tiny(dst, src, size);
}
#endif

static CPINLINE void swoole_string_cpy(seriaString *str, void *mem, size_t len)
{
    swoole_check_size(str, len + 15L);
    //example:13+15=28   28& 11111111 11111111 11111111 11110000
    //str->offset = ((str->offset + 15L) & ~15L);
    //    swoole_memcspy_fast(str->buffer + str->offset, mem, len);
    memcpy(str->buffer + str->offset, mem, len);
    str->offset = len + str->offset;
}

static CPINLINE void swoole_set_zend_value(seriaString *str, void *value)
{
    swoole_check_size(str, sizeof (zend_value));
    *(zend_value*) (str->buffer + str->offset) = *((zend_value*) value);
    str->offset = sizeof (zend_value) + str->offset;
}

static CPINLINE void swoole_serialize_long(seriaString *buffer, zval *zvalue, SBucketType* type)
{
    zend_long value = Z_LVAL_P(zvalue);
    //01111111 - 11111111
    if (value <= 0x7f && value >= -0x7f)
    {
        type->data_len = 0;
        SERIA_SET_ENTRY_TYPE_WITH_MINUS(buffer, value);
    }
    else if (value <= 0x7fff && value >= -0x7fff)
    {
        type->data_len = 1;
        SERIA_SET_ENTRY_SHORT_WITH_MINUS(buffer, value);
    }
    else if (value <= 0x7fffffff && value >= -0x7fffffff)
    {
        type->data_len = 2;
        SERIA_SET_ENTRY_SIZE4_WITH_MINUS(buffer, value);
    }
    else
    {
        type->data_len = 3;
        swoole_string_cpy(buffer, &zvalue->value, sizeof (zend_value));
    }

}

static CPINLINE void* swoole_unserialize_long(void *buffer, zval *ret_value, SBucketType type)
{
    if (type.data_len == 0)
    {//1 byte
        Z_LVAL_P(ret_value) = *((char*) buffer);
        buffer += sizeof (char);
    }
    else if (type.data_len == 1)
    {//2 byte
        Z_LVAL_P(ret_value) = *((short*) buffer);
        buffer += sizeof (short);
    }
    else if (type.data_len == 2)
    {//4 byte
        Z_LVAL_P(ret_value) = *((int32_t *) buffer);
        buffer += sizeof (int32_t);
    }
    else
    {//8 byte
        ret_value->value = *((zend_value*) buffer);
        buffer += sizeof (zend_value);
    }
    return buffer;
}

static uint32_t CPINLINE cp_zend_hash_check_size(uint32_t nSize)
{
#if defined(ZEND_WIN32)
    unsigned long index;
#endif

    /* Use big enough power of 2 */
    /* size should be between HT_MIN_SIZE and HT_MAX_SIZE */
    if (nSize < HT_MIN_SIZE)
    {
        nSize = HT_MIN_SIZE;
    }//    else if (UNEXPECTED(nSize >= 1000000))
    else if (UNEXPECTED(nSize >= HT_MAX_SIZE))
    {
        php_error_docref(NULL TSRMLS_CC, E_NOTICE, "invalid unserialize data");
        return 0;
    }

#if defined(ZEND_WIN32)
    if (BitScanReverse(&index, nSize - 1))
    {
        return 0x2 << ((31 - index) ^ 0x1f);
    }
    else
    {
        /* nSize is ensured to be in the valid range, fall back to it
           rather than using an undefined bis scan result. */
        return nSize;
    }
#elif (defined(__GNUC__) || __has_builtin(__builtin_clz))  && defined(PHP_HAVE_BUILTIN_CLZ)
    return 0x2 << (__builtin_clz(nSize - 1) ^ 0x1f);
#else
    nSize -= 1;
    nSize |= (nSize >> 1);
    nSize |= (nSize >> 2);
    nSize |= (nSize >> 4);
    nSize |= (nSize >> 8);
    nSize |= (nSize >> 16);
    return nSize + 1;
#endif
}

static CPINLINE void swoole_mini_filter_clear()
{
    if (swSeriaG.pack_string)
    {
        memset(&mini_filter, 0, sizeof (mini_filter));
        if (bigger_filter)
        {
            efree(bigger_filter);
            bigger_filter = NULL;

        }
        memset(&swSeriaG.filter, 0, sizeof (struct _swMinFilter));
    }
}

static CPINLINE void swoole_make_bigger_filter_size()
{
    if (FILTER_SIZE <= swSeriaG.filter.mini_fillter_miss_cnt &&
            swSeriaG.filter.mini_fillter_find_cnt < swSeriaG.filter.mini_fillter_miss_cnt)
        //        if (FILTER_SIZE <= swSeriaG.filter.mini_fillter_miss_cnt &&
        //                (swSeriaG.filter.mini_fillter_find_cnt / swSeriaG.filter.mini_fillter_miss_cnt) < 1)
    {
        swSeriaG.filter.bigger_fillter_size = swSeriaG.filter.mini_fillter_miss_cnt * 128;
        bigger_filter = (swPoolstr*) ecalloc(1, sizeof (swPoolstr) * swSeriaG.filter.bigger_fillter_size);
        memcpy(bigger_filter, &mini_filter, sizeof (mini_filter));
    }
}

static CPINLINE void swoole_mini_filter_add(zend_string *zstr, size_t offset, zend_uchar byte)
{
    if (swSeriaG.pack_string)
    {
        offset -= _STR_HEADER_SIZE;
        //head 3bit is overhead
        if (offset >= 0x1fffffff)
        {
            return;
        }
        if (bigger_filter)
        {
            uint32_t mod_big = zstr->h & (swSeriaG.filter.bigger_fillter_size - 1);

            bigger_filter[mod_big].offset = offset << 3;
            if (offset <= 0x1fff)
            {
                bigger_filter[mod_big].offset |= byte;
            }
            else
            {
                bigger_filter[mod_big].offset |= (byte | 4);
            }
            bigger_filter[mod_big].str = zstr;
        }
        else
        {
            uint16_t mod = zstr->h & (FILTER_SIZE - 1);
            //repalce it is effective,cause the principle of locality
            mini_filter[mod].offset = offset << 3;
            if (offset <= 0x1fff)
            {
                mini_filter[mod].offset |= byte;
            }
            else
            {
                mini_filter[mod].offset |= (byte | 4);
            }
            mini_filter[mod].str = zstr;
            swSeriaG.filter.mini_fillter_miss_cnt++;
            swoole_make_bigger_filter_size();
        }
    }

}

static CPINLINE swPoolstr* swoole_mini_filter_find(zend_string *zstr)
{
    if (swSeriaG.pack_string)
    {
        zend_ulong h = zend_string_hash_val(zstr);
        swPoolstr* str = NULL;
        if (bigger_filter)
        {
            str = &bigger_filter[h & (swSeriaG.filter.bigger_fillter_size - 1)];
        }
        else
        {
            str = &mini_filter[h & (FILTER_SIZE - 1)];
        }

        if (!str->str)
        {
            return NULL;
        }

        if (str->str->h == h &&
                zstr->len == str->str->len &&
                memcmp(zstr->val, str->str->val, zstr->len) == 0)
        {
            swSeriaG.filter.mini_fillter_find_cnt++;
            return str;
        }
        else
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }
}

/*
 * arr layout
 * type|key?|bucketlen|buckets
 */
static CPINLINE void seria_array_type(zend_array *ht, seriaString *buffer, size_t type_offset, size_t blen_offset)
{
    buffer->offset = blen_offset;
    if (ht->nNumOfElements <= 0xff)
    {
        ((SBucketType*) (buffer->buffer + type_offset))->data_len = 1;
        SERIA_SET_ENTRY_TYPE(buffer, ht->nNumOfElements)
    }
    else if (ht->nNumOfElements <= 0xffff)
    {
        ((SBucketType*) (buffer->buffer + type_offset))->data_len = 2;
        SERIA_SET_ENTRY_SHORT(buffer, ht->nNumOfElements);
    }
    else
    {
        ((SBucketType*) (buffer->buffer + type_offset))->data_len = 0;
        swoole_string_cpy(buffer, &ht->nNumOfElements, sizeof (uint32_t));
    }
}

/*
 * buffer is bucket len addr
 */
static CPINLINE void* get_array_real_len(void *buffer, zend_uchar data_len, uint32_t *nNumOfElements)
{
    if (data_len == 1)
    {
        *nNumOfElements = *((zend_uchar*) buffer);
        return buffer + sizeof (zend_uchar);
    }
    else if (data_len == 2)
    {
        *nNumOfElements = *((unsigned short*) buffer);
        return buffer + sizeof (short);
    }
    else
    {
        *nNumOfElements = *((uint32_t*) buffer);
        return buffer + sizeof (uint32_t);
    }
}

static CPINLINE void * get_pack_string_len_addr(void ** buffer, size_t *strlen)
{

    uint8_t overhead = (*(uint8_t*) * buffer);
    uint32_t real_offset;
    uint8_t len_byte;

    if (overhead & 4)
    {
        real_offset = (*(uint32_t*) * buffer) >> 3;
        len_byte = overhead & 3;
        (*buffer) += 4;
    }
    else
    {
        real_offset = (*(uint16_t*) * buffer) >> 3;
        len_byte = overhead & 3;
        (*buffer) += 2;
    }
    void *str_pool_addr = unser_start + real_offset;
    if (len_byte == 1)
    {
        *strlen = *((zend_uchar*) str_pool_addr);
        str_pool_addr = str_pool_addr + sizeof (zend_uchar);
    }
    else if (len_byte == 2)
    {
        *strlen = *((unsigned short*) str_pool_addr);
        str_pool_addr = str_pool_addr + sizeof (unsigned short);
    }
    else
    {
        *strlen = *((size_t*) str_pool_addr);
        str_pool_addr = str_pool_addr + sizeof (size_t);
    }
    //    size_t tmp = *strlen;
    return str_pool_addr;
}

/*
 * array
 */

static void* swoole_unserialize_arr(void *buffer, zval *zvalue, uint32_t nNumOfElements, long flag)
{
    //Initialize zend array
    zend_ulong h, nIndex, max_index = 0;
    uint32_t size = cp_zend_hash_check_size(nNumOfElements);
    if (!size)
    {
        return NULL;
    }
    if (!buffer)
    {
        php_error_docref(NULL TSRMLS_CC, E_NOTICE, "illegal unserialize data");
        return NULL;
    }
    ZVAL_NEW_ARR(zvalue);
    //Initialize buckets
    zend_array *ht = Z_ARR_P(zvalue);
    ht->nTableSize = size;
    ht->nNumUsed = nNumOfElements;
    ht->nNumOfElements = nNumOfElements;
    ht->nNextFreeElement = 0;
    ht->u.flags = HASH_FLAG_APPLY_PROTECTION;
    ht->nTableMask = -(ht->nTableSize);
    ht->pDestructor = ZVAL_PTR_DTOR;

    GC_REFCOUNT(ht) = 1;
    GC_TYPE_INFO(ht) = IS_ARRAY;
    // if (ht->nNumUsed)
    //{
    //    void *arData = ecalloc(1, len);
    HT_SET_DATA_ADDR(ht, emalloc(HT_SIZE(ht)));
    ht->u.flags |= HASH_FLAG_INITIALIZED;
    int ht_hash_size = HT_HASH_SIZE((ht)->nTableMask);
    if (ht_hash_size <= 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_NOTICE, "illegal unserialize data");
        return NULL;
    }
    HT_HASH_RESET(ht);
    //}


    int idx;
    Bucket *p;
    for(idx = 0; idx < nNumOfElements; idx++)
    {
        if (!buffer)
        {
            php_error_docref(NULL TSRMLS_CC, E_NOTICE, "illegal array unserialize data");
            return NULL;
        }
        SBucketType type = *((SBucketType*) buffer);
        buffer += sizeof (SBucketType);
        p = ht->arData + idx;
        /* Initialize key */
        if (type.key_type == KEY_TYPE_STRING)
        {
            size_t key_len;
            if (type.key_len == 3)
            {//read the same mem
                void *str_pool_addr = get_pack_string_len_addr(&buffer, &key_len);
                p->key = zend_string_init((char*) str_pool_addr, key_len, 0);
                h = zend_inline_hash_func((char*) str_pool_addr, key_len);
                p->key->h = p->h = h;
            }
            else
            {//move step
                if (type.key_len == 1)
                {
                    key_len = *((zend_uchar*) buffer);
                    buffer += sizeof (zend_uchar);
                }
                else if (type.key_len == 2)
                {
                    key_len = *((unsigned short*) buffer);
                    buffer += sizeof (unsigned short);
                }
                else
                {
                    key_len = *((size_t*) buffer);
                    buffer += sizeof (size_t);
                }
                p->key = zend_string_init((char*) buffer, key_len, 0);
                //           h = zend_inline_hash_func((char*) buffer, key_len);
                h = zend_inline_hash_func((char*) buffer, key_len);
                buffer += key_len;
                p->key->h = p->h = h;
            }
        }
        else
        {
            if (type.key_len == 0)
            {
                //means pack
                h = p->h = idx;
                p->key = NULL;
                max_index = p->h + 1;
                //                ht->u.flags |= HASH_FLAG_PACKED;
            }
            else
            {
                if (type.key_len == 1)
                {
                    h = *((zend_uchar*) buffer);
                    buffer += sizeof (zend_uchar);
                }
                else if (type.key_len == 2)
                {
                    h = *((unsigned short*) buffer);
                    buffer += sizeof (unsigned short);
                }
                else
                {
                    h = *((zend_ulong*) buffer);
                    buffer += sizeof (zend_ulong);
                }
                p->h = h;
                p->key = NULL;
                if (h >= max_index)
                {
                    max_index = h + 1;
                }
            }
        }
        /* Initialize hash */
        nIndex = h | ht->nTableMask;
        Z_NEXT(p->val) = HT_HASH(ht, nIndex);
        HT_HASH(ht, nIndex) = HT_IDX_TO_HASH(idx);

        /* Initialize data type */
        p->val.u1.v.type = type.data_type;
        Z_TYPE_FLAGS(p->val) = 0;

        /* Initialize data */
        if (type.data_type == IS_STRING)
        {
            size_t data_len;
            if (type.data_len == 3)
            {//read the same mem
                void *str_pool_addr = get_pack_string_len_addr(&buffer, &data_len);
                p->val.value.str = zend_string_init((char*) str_pool_addr, data_len, 0);
            }
            else
            {
                if (type.data_len == 1)
                {
                    data_len = *((zend_uchar*) buffer);
                    buffer += sizeof (zend_uchar);
                }
                else if (type.data_len == 2)
                {
                    data_len = *((unsigned short*) buffer);
                    buffer += sizeof (unsigned short);
                }
                else
                {
                    data_len = *((size_t*) buffer);
                    buffer += sizeof (size_t);
                }
                p->val.value.str = zend_string_init((char*) buffer, data_len, 0);
                buffer += data_len;
            }
            Z_TYPE_INFO(p->val) = IS_STRING_EX;
        }
        else if (type.data_type == IS_ARRAY)
        {
            uint32_t num = 0;
            buffer = get_array_real_len(buffer, type.data_len, &num);
            buffer = swoole_unserialize_arr(buffer, &p->val, num, flag);
        }
        else if (type.data_type == IS_LONG)
        {
            buffer = swoole_unserialize_long(buffer, &p->val, type);
        }
        else if (type.data_type == IS_DOUBLE)
        {
            p->val.value = *((zend_value*) buffer);
            buffer += sizeof (zend_value);
        }
        else if (type.data_type == IS_UNDEF)
        {
            buffer = swoole_unserialize_object(buffer, &p->val, type.data_len, NULL, flag);
            Z_TYPE_INFO(p->val) = IS_OBJECT_EX;
        }

    }
    ht->nNextFreeElement = max_index;

    return buffer;

}

/*
 * arr layout
 * type|key?|bucketlen|buckets
 */
static void swoole_serialize_arr(seriaString *buffer, zend_array *zvalue)
{
    zval *data;
    zend_string *key;
    zend_ulong index;
    swPoolstr *swStr = NULL;
    zend_uchar is_pack = zvalue->u.flags & HASH_FLAG_PACKED;

    ZEND_HASH_FOREACH_KEY_VAL(zvalue, index, key, data)
    {
        SBucketType type = {0};
        type.data_type = Z_TYPE_P(data);
        //start point
        size_t p = buffer->offset;

        if (is_pack && zvalue->nNextFreeElement == zvalue->nNumOfElements)
        {
            type.key_type = KEY_TYPE_INDEX;
            type.key_len = 0;
            SERIA_SET_ENTRY_TYPE(buffer, type);
        }
        else
        {
            //seria key
            if (key)
            {
                type.key_type = KEY_TYPE_STRING;
                if ((swStr = swoole_mini_filter_find(key)))
                {
                    type.key_len = 3; //means use same string
                    SERIA_SET_ENTRY_TYPE(buffer, type);
                    if (swStr->offset & 4)
                    {
                        SERIA_SET_ENTRY_SIZE4(buffer, swStr->offset);
                    }
                    else
                    {
                        SERIA_SET_ENTRY_SHORT(buffer, swStr->offset);
                    }
                }
                else
                {
                    if (key->len <= 0xff)
                    {
                        type.key_len = 1;
                        SERIA_SET_ENTRY_TYPE(buffer, type);
                        swoole_mini_filter_add(key, buffer->offset, 1);
                        SERIA_SET_ENTRY_TYPE(buffer, key->len);
                        swoole_string_cpy(buffer, key->val, key->len);
                    }
                    else if (key->len <= 0xffff)
                    {//if more than this  don't need optimize
                        type.key_len = 2;
                        SERIA_SET_ENTRY_TYPE(buffer, type);
                        swoole_mini_filter_add(key, buffer->offset, 2);
                        SERIA_SET_ENTRY_SHORT(buffer, key->len);
                        swoole_string_cpy(buffer, key->val, key->len);
                    }
                    else
                    {
                        type.key_len = 0;
                        SERIA_SET_ENTRY_TYPE(buffer, type);
                        swoole_mini_filter_add(key, buffer->offset, 3);
                        swoole_string_cpy(buffer, key + XtOffsetOf(zend_string, len), sizeof (size_t) + key->len);
                    }
                }
            }
            else
            {
                type.key_type = KEY_TYPE_INDEX;
                if (index <= 0xff)
                {
                    type.key_len = 1;
                    SERIA_SET_ENTRY_TYPE(buffer, type);
                    SERIA_SET_ENTRY_TYPE(buffer, index);
                }
                else if (index <= 0xffff)
                {
                    type.key_len = 2;
                    SERIA_SET_ENTRY_TYPE(buffer, type);
                    SERIA_SET_ENTRY_SHORT(buffer, index);
                }
                else
                {
                    type.key_len = 3;
                    SERIA_SET_ENTRY_TYPE(buffer, type);
                    SERIA_SET_ENTRY_ULONG(buffer, index);
                }

            }
        }
        //seria data
try_again:
        switch (Z_TYPE_P(data))
        {
            case IS_STRING:
            {
                if ((swStr = swoole_mini_filter_find(Z_STR_P(data))))
                {
                    ((SBucketType*) (buffer->buffer + p))->data_len = 3; //means use same string
                    if (swStr->offset & 4)
                    {
                        SERIA_SET_ENTRY_SIZE4(buffer, swStr->offset);
                    }
                    else
                    {
                        SERIA_SET_ENTRY_SHORT(buffer, swStr->offset);
                    }
                }
                else
                {
                    if (Z_STRLEN_P(data) <= 0xff)
                    {
                        ((SBucketType*) (buffer->buffer + p))->data_len = 1;
                        swoole_mini_filter_add(Z_STR_P(data), buffer->offset, 1);
                        SERIA_SET_ENTRY_TYPE(buffer, Z_STRLEN_P(data));
                        swoole_string_cpy(buffer, Z_STRVAL_P(data), Z_STRLEN_P(data));
                    }
                    else if (Z_STRLEN_P(data) <= 0xffff)
                    {
                        ((SBucketType*) (buffer->buffer + p))->data_len = 2;
                        swoole_mini_filter_add(Z_STR_P(data), buffer->offset, 2);
                        SERIA_SET_ENTRY_SHORT(buffer, Z_STRLEN_P(data));
                        swoole_string_cpy(buffer, Z_STRVAL_P(data), Z_STRLEN_P(data));
                    }
                    else
                    {//if more than this  don't need optimize
                        ((SBucketType*) (buffer->buffer + p))->data_len = 0;
                        swoole_mini_filter_add(Z_STR_P(data), buffer->offset, 3);
                        swoole_string_cpy(buffer, (char*) Z_STR_P(data) + XtOffsetOf(zend_string, len), sizeof (size_t) + Z_STRLEN_P(data));
                    }
                }
                break;
            }
            case IS_LONG:
            {
                SBucketType* long_type = (SBucketType*) (buffer->buffer + p);
                swoole_serialize_long(buffer, data, long_type);
                break;
            }
            case IS_DOUBLE:
                swoole_set_zend_value(buffer, &(data->value));
                break;
            case IS_REFERENCE:
                data = Z_REFVAL_P(data);
                ((SBucketType*) (buffer->buffer + p))->data_type = Z_TYPE_P(data);
                goto try_again;
                break;
            case IS_ARRAY:
            {
                zend_array *ht = Z_ARRVAL_P(data);

                if (ZEND_HASH_GET_APPLY_COUNT(ht) > 1)
                {
                    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "the array has cycle ref");
                }
                else
                {
                    seria_array_type(ht, buffer, p, buffer->offset);
                    if (ZEND_HASH_APPLY_PROTECTION(ht))
                    {
                        ZEND_HASH_INC_APPLY_COUNT(ht);
                        swoole_serialize_arr(buffer, ht);
                        ZEND_HASH_DEC_APPLY_COUNT(ht);
                    }
                    else
                    {
                        swoole_serialize_arr(buffer, ht);
                    }

                }
                break;
            }
                //object propterty table is this type
            case IS_INDIRECT:
                data = Z_INDIRECT_P(data);
                ((SBucketType*) (buffer->buffer + p))->data_type = Z_TYPE_P(data);
                goto try_again;
                break;
            case IS_OBJECT:
            {
                /*
                 * layout
                 * type | key | namelen | name | bucket len |buckets
                 */
                ((SBucketType*) (buffer->buffer + p))->data_type = IS_UNDEF;

                if (ZEND_HASH_APPLY_PROTECTION(Z_OBJPROP_P(data)))
                {
                    ZEND_HASH_INC_APPLY_COUNT(Z_OBJPROP_P(data));
                    swoole_serialize_object(buffer, data, p);
                    ZEND_HASH_DEC_APPLY_COUNT(Z_OBJPROP_P(data));
                }
                else
                {
                    swoole_serialize_object(buffer, data, p);
                }

                break;
            }
            default://
                break;

        }

    }
    ZEND_HASH_FOREACH_END();
}

/*
 * string
 */
static CPINLINE void swoole_serialize_string(seriaString *buffer, zval *zvalue)
{

    swoole_string_cpy(buffer, Z_STRVAL_P(zvalue), Z_STRLEN_P(zvalue));
}

static CPINLINE zend_string* swoole_unserialize_string(void *buffer, size_t len)
{

    return zend_string_init(buffer, len, 0);
}

/*
 * raw
 */
static CPINLINE void swoole_unserialize_raw(void *buffer, zval *zvalue)
{

    memcpy(&zvalue->value, buffer, sizeof (zend_value));
}

#if 0
/*
 * null
 */
static CPINLINE void swoole_unserialize_null(void *buffer, zval *zvalue)
{

    memcpy(&zvalue->value, buffer, sizeof (zend_value));
}
#endif

static CPINLINE void swoole_serialize_raw(seriaString *buffer, zval *zvalue)
{

    swoole_string_cpy(buffer, &zvalue->value, sizeof (zend_value));
}

/*
 * obj layout
 * type|bucket key|name len| name| buket len |buckets
 */
static void swoole_serialize_object(seriaString *buffer, zval *obj, size_t start)
{
    zend_string *name = Z_OBJCE_P(obj)->name;
    if (ZEND_HASH_GET_APPLY_COUNT(Z_OBJPROP_P(obj)) > 1)
    {
        zend_throw_exception_ex(NULL, 0, "the object %s has cycle ref.", name->val);
        return;
    }
    if (name->len > 0xffff)
    {//so long?
        zend_throw_exception_ex(NULL, 0, "the object name is too long.");
    }
    else
    {
        SERIA_SET_ENTRY_SHORT(buffer, name->len);
        swoole_string_cpy(buffer, name->val, name->len);
    }

    zend_class_entry *ce = Z_OBJ_P(obj)->ce;
    if (ce && zend_hash_exists(&ce->function_table, Z_STR(swSeriaG.sleep_fname)))
    {
        zval retval;
        if (call_user_function_ex(NULL, obj, &swSeriaG.sleep_fname, &retval, 0, 0, 1, NULL) == SUCCESS)
        {
            if (EG(exception))
            {
                zval_dtor(&retval);
                return;
            }
            if (Z_TYPE(retval) == IS_ARRAY)
            {
                zend_string *prop_key;
                zval *prop_value, *sleep_value;
                const char *prop_name, *class_name;
                size_t prop_key_len;
                int got_num = 0;

                //for the zero malloc
                zend_array tmp_arr;
                zend_array *ht = (zend_array *) & tmp_arr;
                _zend_hash_init(ht, zend_hash_num_elements(Z_ARRVAL(retval)), ZVAL_PTR_DTOR, 0 ZEND_FILE_LINE_CC);
                ht->nTableMask = -(ht)->nTableSize;
                ALLOCA_FLAG(use_heap);
                void *ht_addr = do_alloca(HT_SIZE(ht), use_heap);
                HT_SET_DATA_ADDR(ht, ht_addr);
                ht->u.flags |= HASH_FLAG_INITIALIZED;
                HT_HASH_RESET(ht);

                //just clean property do not add null when does not exist
                //we double for each, cause we do not malloc  and release it

                ZEND_HASH_FOREACH_STR_KEY_VAL(Z_OBJPROP_P(obj), prop_key, prop_value)
                {
                    //get origin property name
                    zend_unmangle_property_name_ex(prop_key, &class_name, &prop_name, &prop_key_len);

                    ZEND_HASH_FOREACH_VAL(Z_ARRVAL(retval), sleep_value)
                    {
                        if (Z_TYPE_P(sleep_value) == IS_STRING &&
                                Z_STRLEN_P(sleep_value) == prop_key_len &&
                                memcmp(Z_STRVAL_P(sleep_value), prop_name, prop_key_len) == 0)
                        {
                            got_num++;
                            //add mangle key,unmangle in unseria
                            _zend_hash_add_or_update(ht, prop_key, prop_value, HASH_UPDATE ZEND_FILE_LINE_CC);

                            break;
                        }

                    }
                    ZEND_HASH_FOREACH_END();

                }
                ZEND_HASH_FOREACH_END();

                //there some member not in property
                if (zend_hash_num_elements(Z_ARRVAL(retval)) > got_num)
                {
                    php_error_docref(NULL TSRMLS_CC, E_NOTICE, "__sleep() retrun a member but does not exist in property");

                }
                seria_array_type(ht, buffer, start, buffer->offset);
                swoole_serialize_arr(buffer, ht);
                ZSTR_ALLOCA_FREE(ht_addr, use_heap);
                zval_dtor(&retval);
                return;

            }
            else
            {
                php_error_docref(NULL TSRMLS_CC, E_NOTICE, " __sleep should return an array only containing the "
                        "names of instance-variables to serialize");
                zval_dtor(&retval);
            }

        }
    }
    seria_array_type(Z_OBJPROP_P(obj), buffer, start, buffer->offset);
    swoole_serialize_arr(buffer, Z_OBJPROP_P(obj));
    //    printf("hash2 %u\n",ce->properties_info.arData[0].key->h);
}

/*
 * for the zero malloc
 */
static CPINLINE zend_string * swoole_string_init(const char *str, size_t len)
{
    ALLOCA_FLAG(use_heap);
    zend_string *ret;
    ZSTR_ALLOCA_INIT(ret, str, len, use_heap);

    return ret;
}

/*
 * for the zero malloc
 */
static CPINLINE void swoole_string_release(zend_string *str)
{
    //if dont support alloc 0 will ignore
    //if support alloc size is definitely < ZEND_ALLOCA_MAX_SIZE
    ZSTR_ALLOCA_FREE(str, 0);
}

static CPINLINE zend_class_entry* swoole_try_get_ce(zend_string *class_name)
{
    //user class , do not support incomplete class now
    zend_class_entry *ce = zend_lookup_class(class_name);
    if (ce)
    {
        return ce;
    }
    // try call unserialize callback and retry lookup
    zval user_func, args[1], retval;
    zend_string *fname = swoole_string_init(PG(unserialize_callback_func), strlen(PG(unserialize_callback_func)));
    Z_STR(user_func) = fname;
    Z_TYPE_INFO(user_func) = IS_STRING_EX;
    ZVAL_STR(&args[0], class_name);

    call_user_function_ex(CG(function_table), NULL, &user_func, &retval, 1, args, 0, NULL);

    swoole_string_release(fname);

    //user class , do not support incomplete class now
    ce = zend_lookup_class(class_name);
    if (!ce)
    {
        zend_throw_exception_ex(NULL, 0, "can not find class %s", class_name->val TSRMLS_CC);
        return NULL;
    }
    else
    {
        return ce;
    }
}

/*
 * obj layout
 * type| key[0|1] |name len| name| buket len |buckets
 */
static void* swoole_unserialize_object(void *buffer, zval *return_value, zend_uchar bucket_len, zval *args, long flag)
{
    zval property;
    uint32_t arr_num = 0;
    size_t name_len = *((unsigned short*) buffer);
    if (!name_len)
    {
        php_error_docref(NULL TSRMLS_CC, E_NOTICE, "illegal unserialize data");
        return NULL;
    }
    buffer += 2;
    zend_string *class_name;
    if (flag == UNSERIALIZE_OBJECT_TO_STDCLASS) 
    {
        class_name = swoole_string_init("StdClass", 8);
    } 
    else 
    {
        class_name = swoole_string_init((char*) buffer, name_len);
    }
    buffer += name_len;
    zend_class_entry *ce = swoole_try_get_ce(class_name);
    swoole_string_release(class_name);

    if (!ce)
    {
        return NULL;
    }

    buffer = get_array_real_len(buffer, bucket_len, &arr_num);
    buffer = swoole_unserialize_arr(buffer, &property, arr_num, flag);

    object_init_ex(return_value, ce);

    zval *data;
    const zend_string *key;
    zend_ulong index;

    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL(property), index, key, data)
    {
        const char *prop_name, *tmp;
        size_t prop_len;
        if (key)
        {
            zend_unmangle_property_name_ex(key, &tmp, &prop_name, &prop_len);
            zend_update_property(ce, return_value, prop_name, prop_len, data);
        }
        else
        {
            zend_hash_next_index_insert(Z_OBJPROP_P(return_value), data);
        }
    }
    (void) index;
    ZEND_HASH_FOREACH_END();
    zval_dtor(&property);

    if (ce->constructor)
    {
        //        zend_fcall_info fci = {0};
        //        zend_fcall_info_cache fcc = {0};
        //        fci.size = sizeof (zend_fcall_info);
        //        zval retval;
        //        ZVAL_UNDEF(&fci.function_name);
        //        fci.retval = &retval;
        //        fci.param_count = 0;
        //        fci.params = NULL;
        //        fci.no_separation = 1;
        //        fci.object = Z_OBJ_P(return_value);
        //
        //        zend_fcall_info_args_ex(&fci, ce->constructor, args);
        //
        //        fcc.initialized = 1;
        //        fcc.function_handler = ce->constructor;
        //        //        fcc.calling_scope = EG(scope);
        //        fcc.called_scope = Z_OBJCE_P(return_value);
        //        fcc.object = Z_OBJ_P(return_value);
        //
        //        if (zend_call_function(&fci, &fcc) == FAILURE)
        //        {
        //            zend_throw_exception_ex(NULL, 0, "could not call class constructor");
        //        }
        //        zend_fcall_info_args_clear(&fci, 1);
    }


    //call object __wakeup
    if (zend_hash_str_exists(&ce->function_table, "__wakeup", sizeof ("__wakeup") - 1))
    {
        zval ret, wakeup;
        zend_string *fname = swoole_string_init("__wakeup", sizeof ("__wakeup") - 1);
        Z_STR(wakeup) = fname;
        Z_TYPE_INFO(wakeup) = IS_STRING_EX;
        call_user_function_ex(CG(function_table), return_value, &wakeup, &ret, 0, NULL, 1, NULL);
        swoole_string_release(fname);
        zval_ptr_dtor(&ret);
    }

    return buffer;

}

/*
 * dispatch
 */

static CPINLINE void swoole_seria_dispatch(seriaString *buffer, zval *zvalue)
{
again:
    switch (Z_TYPE_P(zvalue))
    {
        case IS_NULL:
        case IS_TRUE:
        case IS_FALSE:
            break;
        case IS_LONG:
        {
            SBucketType* type = (SBucketType*) (buffer->buffer + _STR_HEADER_SIZE);
            swoole_serialize_long(buffer, zvalue, type);
            break;
        }
        case IS_DOUBLE:
            swoole_serialize_raw(buffer, zvalue);
            break;
        case IS_STRING:
            swoole_serialize_string(buffer, zvalue);
            break;
        case IS_ARRAY:
        {
            seria_array_type(Z_ARRVAL_P(zvalue), buffer, _STR_HEADER_SIZE, _STR_HEADER_SIZE + 1);
            swoole_serialize_arr(buffer, Z_ARRVAL_P(zvalue));
            swoole_string_cpy(buffer, SWOOLE_SERI_EOF, 3);
            swoole_mini_filter_clear();
            break;
        }
        case IS_REFERENCE:
            zvalue = Z_REFVAL_P(zvalue);
            goto again;
            break;
        case IS_OBJECT:
        {
            SBucketType* type = (SBucketType*) (buffer->buffer + _STR_HEADER_SIZE);
            type->data_type = IS_UNDEF;
            swoole_serialize_object(buffer, zvalue, _STR_HEADER_SIZE);
            swoole_string_cpy(buffer, SWOOLE_SERI_EOF, 3);
            swoole_mini_filter_clear();
            break;
        }
        default:
            php_error_docref(NULL TSRMLS_CC, E_NOTICE, "the type is not supported by swoole serialize.");

            break;
    }
}

PHPAPI zend_string* php_swoole_serialize(zval *zvalue)
{

    seriaString str;
    swoole_string_new(SERIA_SIZE, &str, Z_TYPE_P(zvalue));
    swoole_seria_dispatch(&str, zvalue); //serialize into a string
    zend_string *z_str = (zend_string *) str.buffer;

    z_str->val[str.offset] = '\0';
    z_str->len = str.offset - _STR_HEADER_SIZE;
    z_str->h = 0;
    GC_REFCOUNT(z_str) = 1;
    GC_TYPE_INFO(z_str) = IS_STRING_EX;

    return z_str;
}

static CPINLINE int swoole_seria_check_eof(void *buffer, size_t len)
{
    void *eof_str = buffer - sizeof (SBucketType) + len - 3;
    if (memcmp(eof_str, SWOOLE_SERI_EOF, 3) == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

/*
 * buffer is seria string buffer
 * len is string len
 * return_value is unseria bucket
 * args is for the object ctor (can be NULL)
 */
PHPAPI int php_swoole_unserialize(void *buffer, size_t len, zval *return_value, zval *object_args, long flag)
{
    SBucketType type = *(SBucketType*) (buffer);
    zend_uchar real_type = type.data_type;
    buffer += sizeof (SBucketType);
    switch (real_type)
    {
        case IS_NULL:
        case IS_TRUE:
        case IS_FALSE:
            Z_TYPE_INFO_P(return_value) = real_type;
            break;
        case IS_LONG:
            swoole_unserialize_long(buffer, return_value, type);
            Z_TYPE_INFO_P(return_value) = real_type;
            break;
        case IS_DOUBLE:
            swoole_unserialize_raw(buffer, return_value);
            Z_TYPE_INFO_P(return_value) = real_type;
            break;
        case IS_STRING:
            len -= sizeof (SBucketType);
            zend_string *str = swoole_unserialize_string(buffer, len);
            ZVAL_STR(return_value, str);
            break;
        case IS_ARRAY:
        {
            if (swoole_seria_check_eof(buffer, len) < 0)
            {
                  php_error_docref(NULL TSRMLS_CC, E_NOTICE, "detect the error eof");
                  return SW_FALSE;
            }
            unser_start = buffer - sizeof (SBucketType);
            uint32_t num = 0;
            buffer = get_array_real_len(buffer, type.data_len, &num);
            if (!swoole_unserialize_arr(buffer, return_value, num, flag))
            {
                return SW_FALSE;
            }
            break;
        }
        case IS_UNDEF:
            if (swoole_seria_check_eof(buffer, len) < 0)
            {
                  php_error_docref(NULL TSRMLS_CC, E_NOTICE, "detect the error eof");
                  return SW_FALSE;
            }
            unser_start = buffer - sizeof (SBucketType);
            if (!swoole_unserialize_object(buffer, return_value, type.data_len, object_args, flag))
            {
                return SW_FALSE;
            }
            break;
        default:
            php_error_docref(NULL TSRMLS_CC, E_NOTICE, "the type is not supported by swoole serialize.");
            return SW_FALSE;
    }

    return SW_TRUE;
}

static PHP_METHOD(swoole_serialize, pack)
{
    zval *zvalue;
    zend_size_t is_fast = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|l", &zvalue, &is_fast) == FAILURE)
    {
        RETURN_FALSE;
    }
    swSeriaG.pack_string = !is_fast;
    zend_string *z_str = php_swoole_serialize(zvalue);

    RETURN_STR(z_str);
}

static PHP_METHOD(swoole_serialize, unpack)
{
    char *buffer = NULL;
    size_t arg_len;
    zval *args = NULL; //for object
    long flag = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|la", &buffer, &arg_len, &flag, &args) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (!php_swoole_unserialize(buffer, arg_len, return_value, args, flag))
    {
        RETURN_FALSE;
    }
}

#endif

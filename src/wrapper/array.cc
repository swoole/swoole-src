/*
  +----------------------------------------------------------------------+
  | PHP-X                                                                |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 The Swoole Group                             |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the GPL license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.gnu.org/licenses/                                         |
  | If you did not receive a copy of the GPL3.0 license and are unable   |
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "phpx.h"

using namespace std;

namespace php
{

int array_data_compare(const void *a, const void *b)
{
    Bucket *f;
    Bucket *s;
    zval result;
    zval *first;
    zval *second;

    f = (Bucket *) a;
    s = (Bucket *) b;

    first = &f->val;
    second = &s->val;

    if (UNEXPECTED(Z_TYPE_P(first) == IS_INDIRECT))
    {
        first = Z_INDIRECT_P(first);
    }
    if (UNEXPECTED(Z_TYPE_P(second) == IS_INDIRECT))
    {
        second = Z_INDIRECT_P(second);
    }
    if (compare_function(&result, first, second) == FAILURE)
    {
        return 0;
    }

    ZEND_ASSERT(Z_TYPE(result) == IS_LONG);
    return Z_LVAL(result);
}

Array Array::slice(long offset, long length, bool preserve_keys)
{
    size_t num_in = count();

    if (offset > num_in)
    {
        return Array();
    }
    else if (offset < 0 && (offset = (num_in + offset)) < 0)
    {
        offset = 0;
    }

    if (length < 0)
    {
        length = num_in - offset + length;
    }
    else if (((zend_ulong) offset + (zend_ulong) length) > (unsigned) num_in)
    {
        length = num_in - offset;
    }

    if (length <= 0)
    {
        return Array();
    }

    zend_string *string_key;
    zend_ulong num_key;
    zval *entry;

    zval return_value;
    array_init_size(&return_value, (uint32_t ) length);

    /* Start at the beginning and go until we hit offset */
    int pos = 0;
    if (!preserve_keys && (Z_ARRVAL_P(this->ptr())->u.flags & HASH_FLAG_PACKED))
    {
        zend_hash_real_init(Z_ARRVAL_P(&return_value), 1);
        ZEND_HASH_FILL_PACKED(Z_ARRVAL_P(&return_value))
        {
            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(this->ptr()), entry)
            {
                pos++;
                if (pos <= offset)
                {
                    continue;
                }
                if (pos > offset + length)
                {
                    break;
                }
                ZEND_HASH_FILL_ADD(entry);
                zval_add_ref(entry);
            }
            ZEND_HASH_FOREACH_END();
        }
        ZEND_HASH_FILL_END();
    }
    else
    {
        ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(this->ptr()), num_key, string_key, entry)
        {
            pos++;
            if (pos <= offset)
            {
                continue;
            }
            if (pos > offset + length)
            {
                break;
            }

            if (string_key)
            {
                entry = zend_hash_add_new(Z_ARRVAL_P(&return_value), string_key, entry);
            }
            else
            {
                if (preserve_keys)
                {
                    entry = zend_hash_index_add_new(Z_ARRVAL_P(&return_value), num_key, entry);
                }
                else
                {
                    entry = zend_hash_next_index_insert_new(Z_ARRVAL_P(&return_value), entry);
                }
            }
            zval_add_ref(entry);
        }
        ZEND_HASH_FOREACH_END();
    }
    Array retval(&return_value);
    return retval;
}

}

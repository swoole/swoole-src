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
  | Author: Twosee  <twose@qq.com>                                       |
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "php_swoole_cxx.h"

#ifdef SW_THREAD

#include "swoole_lock.h"

typedef uint32_t ThreadResourceId;
struct ThreadResource;

ThreadResourceId php_swoole_thread_resource_insert(ThreadResource *res);
bool php_swoole_thread_resource_free(ThreadResourceId resource_id, ThreadResource *res);
ThreadResource *php_swoole_thread_resource_fetch(ThreadResourceId resource_id);

void php_swoole_thread_start(zend_string *file, zend_string *argv);
zend_string *php_swoole_thread_serialize(zval *zdata);
bool php_swoole_thread_unserialize(zend_string *data, zval *zv);

zval *php_swoole_thread_get_arguments();

#define EMSG_NO_RESOURCE "resource not found"
#define ECODE_NO_RESOURCE -2

#define IS_STREAM_SOCKET 98
#define IS_SERIALIZED_OBJECT 99

struct ThreadResource {
    uint32_t ref_count;

    ThreadResource() {
        ref_count = 1;
    }

    uint32_t add_ref() {
        return ++ref_count;
    }

    uint32_t del_ref() {
        return --ref_count;
    }
};


struct ArrayItem {
    uint32_t type;
    zend_string *key;
    union {
        zend_string *str;
        zend_long lval;
        double dval;
        zend_string *serialized_object;
    } value;

    ArrayItem(zval *zvalue) {
        key = nullptr;
        value = {};
        store(zvalue);
    }

    void store(zval *zvalue);
    void fetch(zval *return_value);
    void release();

    ~ArrayItem() {
        if (value.str) {
            release();
        }
        if (key) {
            zend_string_release(key);
        }
    }
};

struct ZendArray : ThreadResource {
    swoole::RWLock lock_;
    zend_array ht;

    static void item_dtor(zval *pDest) {
        ArrayItem *item = (ArrayItem *) Z_PTR_P(pDest);
        delete item;
    }

    ZendArray() : ThreadResource(), lock_(0) {
        zend_hash_init(&ht, 0, NULL, item_dtor, 1);
    }

    ~ZendArray() {
        zend_hash_destroy(&ht);
    }

    void clean() {
        lock_.lock();
        zend_hash_clean(&ht);
        lock_.unlock();
    }

    bool index_exists(zend_long index) {
        return index < (zend_long) zend_hash_num_elements(&ht);
    }

    void strkey_offsetGet(zval *zkey, zval *return_value) {
        zend::String skey(zkey);
        lock_.lock_rd();
        ArrayItem *item = (ArrayItem *) zend_hash_find_ptr(&ht, skey.get());
        if (item) {
            item->fetch(return_value);
        }
        lock_.unlock();
    }

    void strkey_offsetExists(zval *zkey, zval *return_value) {
        zend::String skey(zkey);
        lock_.lock_rd();
        RETVAL_BOOL(zend_hash_find_ptr(&ht, skey.get()) != NULL);
        lock_.unlock();
    }

    void strkey_offsetUnset(zval *zkey) {
        zend::String skey(zkey);
        lock_.lock();
        zend_hash_del(&ht, skey.get());
        lock_.unlock();
    }

    void strkey_offsetSet(zval *zkey, zval *zvalue) {
        zend::String skey(zkey);
        auto item = new ArrayItem(zvalue);
        item->key = zend_string_init(skey.val(), skey.len(), 1);
        lock_.lock();
        zend_hash_update_ptr(&ht, item->key, item);
        lock_.unlock();
    }

    void count(zval *return_value) {
        lock_.lock_rd();
        RETVAL_LONG(zend_hash_num_elements(&ht));
        lock_.unlock();
    }

    void keys(zval *return_value) {
        lock_.lock_rd();
        zend_ulong elem_count = zend_hash_num_elements(&ht);
        array_init_size(return_value, elem_count);
        zend_hash_real_init_packed(Z_ARRVAL_P(return_value));
        zend_ulong num_idx;
        zend_string *str_idx;
        zval *entry;
        ZEND_HASH_FILL_PACKED(Z_ARRVAL_P(return_value)) {
            if (HT_IS_PACKED(&ht) && HT_IS_WITHOUT_HOLES(&ht)) {
                /* Optimistic case: range(0..n-1) for vector-like packed array */
                zend_ulong lval = 0;

                for (; lval < elem_count; ++lval) {
                    ZEND_HASH_FILL_SET_LONG(lval);
                    ZEND_HASH_FILL_NEXT();
                }
            } else {
                /* Go through input array and add keys to the return array */
                ZEND_HASH_FOREACH_KEY_VAL(&ht, num_idx, str_idx, entry) {
                    if (str_idx) {
                        ZEND_HASH_FILL_SET_STR(zend_string_init(str_idx->val, str_idx->len, 0));
                    } else {
                        ZEND_HASH_FILL_SET_LONG(num_idx);
                    }
                    ZEND_HASH_FILL_NEXT();
                }
                ZEND_HASH_FOREACH_END();
            }
            (void) entry;
        }
        ZEND_HASH_FILL_END();
        lock_.unlock();
    }

    void intkey_offsetGet(zend_long index, zval *return_value) {
        lock_.lock_rd();
        ArrayItem *item = (ArrayItem *) zend_hash_index_find_ptr(&ht, index);
        if (item) {
            item->fetch(return_value);
        }
        lock_.unlock();
    }

    void intkey_offsetGet(zval *zkey, zval *return_value) {
        intkey_offsetGet(zval_get_long(zkey), return_value);
    }

    void intkey_offsetExists(zval *zkey, zval *return_value) {
        zend_long index = zval_get_long(zkey);
        lock_.lock_rd();
        RETVAL_BOOL(zend_hash_index_find_ptr(&ht, index) != NULL);
        lock_.unlock();
    }

    void intkey_offsetUnset(zval *zkey) {
        zend_long index = zval_get_long(zkey);
        lock_.lock();
        zend_hash_index_del(&ht, index);
        lock_.unlock();
    }

    void intkey_offsetSet(zval *zkey, zval *zvalue) {
        zend_long index = zval_get_long(zkey);
        auto item = new ArrayItem(zvalue);
        lock_.lock();
        zend_hash_index_update_ptr(&ht, index, item);
        lock_.unlock();
    }

    bool index_offsetGet(zval *zkey, zval *return_value) {
        zend_long index = zval_get_long(zkey);
        bool out_of_range = true;
        lock_.lock_rd();
        if (index_exists(index)) {
            out_of_range = false;
            ArrayItem *item = (ArrayItem *) zend_hash_index_find_ptr(&ht, index);
            if (item) {
                item->fetch(return_value);
            }
        }
        lock_.unlock();
        return !out_of_range;
    }

    bool index_offsetSet(zval *zkey, zval *zvalue) {
        zend_long index = ZVAL_IS_NULL(zkey) ? -1 : zval_get_long(zkey);
        auto item = new ArrayItem(zvalue);
        bool success = true;
        lock_.lock();
        if (index > zend_hash_num_elements(&ht)) {
            success = false;
            delete item;
        } else if (index == -1 || index == zend_hash_num_elements(&ht)) {
            zend_hash_next_index_insert_ptr(&ht, item);
        } else {
            zend_hash_index_update_ptr(&ht, index, item);
        }
        lock_.unlock();
        return success;
    }

    void index_offsetExists(zval *zkey, zval *return_value) {
        zend_long index = zval_get_long(zkey);
        lock_.lock_rd();
        RETVAL_BOOL(index_exists(index));
        lock_.unlock();
    }
};

#endif

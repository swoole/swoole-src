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
void php_swoole_thread_bailout(void);

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
    uint32_t type = IS_UNDEF;
    zend_string *key = nullptr;
    union {
        zend_string *str;
        zend_long lval;
        double dval;
        zend_string *serialized_object;
    } value;

    ArrayItem(zval *zvalue) {
        value = {};
        store(zvalue);
    }

    void setKey(zend::String &_key) {
        key = zend_string_init(_key.val(), _key.len(), 1);
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

    bool strkey_exists(zend::String &skey) {
        return zend_hash_find_ptr(&ht, skey.get()) != NULL;
    }

    bool intkey_exists(zend_long index) {
        return zend_hash_index_find_ptr(&ht, index) != NULL;
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
        RETVAL_BOOL(strkey_exists(skey));
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
        item->setKey(skey);
        lock_.lock();
        zend_hash_update_ptr(&ht, item->key, item);
        lock_.unlock();
    }

    void strkey_incr(zval *zkey, zval *zvalue, zval *return_value);
    void intkey_incr(zval *zkey, zval *zvalue, zval *return_value);
    void strkey_decr(zval *zkey, zval *zvalue, zval *return_value);
    void intkey_decr(zval *zkey, zval *zvalue, zval *return_value);
    bool index_incr(zval *zkey, zval *zvalue, zval *return_value);
    bool index_decr(zval *zkey, zval *zvalue, zval *return_value);

    void strkey_add(zval *zkey, zval *zvalue, zval *return_value);
    void intkey_add(zval *zkey, zval *zvalue, zval *return_value);
    void strkey_update(zval *zkey, zval *zvalue, zval *return_value);
    void intkey_update(zval *zkey, zval *zvalue, zval *return_value);

    void count(zval *return_value) {
        lock_.lock_rd();
        RETVAL_LONG(zend_hash_num_elements(&ht));
        lock_.unlock();
    }

    void keys(zval *return_value);

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
        RETVAL_BOOL(intkey_exists(index));
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

    bool index_offsetSet(zval *zkey, zval *zvalue);

    void index_offsetExists(zval *zkey, zval *return_value) {
        zend_long index = zval_get_long(zkey);
        lock_.lock_rd();
        RETVAL_BOOL(index_exists(index));
        lock_.unlock();
    }

    static void incr_update(ArrayItem *item, zval *zvalue, zval *return_value);
    static ArrayItem *incr_create(zval *zvalue, zval *return_value);
};

#define INIT_ARRAY_INCR_PARAMS                                                                                         \
    zval *zkey;                                                                                                        \
    zval zvalue_, *zvalue = NULL;                                                                                      \
                                                                                                                       \
    ZEND_PARSE_PARAMETERS_START(1, 2)                                                                                  \
    Z_PARAM_ZVAL(zkey)                                                                                                 \
    Z_PARAM_OPTIONAL                                                                                                   \
    Z_PARAM_ZVAL(zvalue)                                                                                               \
    ZEND_PARSE_PARAMETERS_END();                                                                                       \
                                                                                                                       \
    if (!zvalue) {                                                                                                     \
        zvalue = &zvalue_;                                                                                             \
        ZVAL_LONG(zvalue, 1);                                                                                          \
    }

#endif

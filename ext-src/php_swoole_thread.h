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
class ThreadResource;
class ZendArray;

extern zend_class_entry *swoole_thread_ce;
extern zend_class_entry *swoole_thread_error_ce;
extern zend_class_entry *swoole_thread_arraylist_ce;
extern zend_class_entry *swoole_thread_atomic_ce;
extern zend_class_entry *swoole_thread_atomic_long_ce;
extern zend_class_entry *swoole_thread_barrier_ce;
extern zend_class_entry *swoole_thread_lock_ce;
extern zend_class_entry *swoole_thread_map_ce;
extern zend_class_entry *swoole_thread_queue_ce;

void php_swoole_thread_start(zend_string *file, ZendArray *argv);
void php_swoole_thread_join(pthread_t ptid);
int php_swoole_thread_get_exit_status(pthread_t ptid);
zend_string *php_swoole_serialize(zval *zdata);
bool php_swoole_unserialize(zend_string *data, zval *zv);
void php_swoole_thread_bailout(void);

ThreadResource *php_swoole_thread_arraylist_cast(zval *zobject);
ThreadResource *php_swoole_thread_map_cast(zval *zobject);
ThreadResource *php_swoole_thread_queue_cast(zval *zobject);
ThreadResource *php_swoole_thread_lock_cast(zval *zobject);
ThreadResource *php_swoole_thread_atomic_cast(zval *zobject);
ThreadResource *php_swoole_thread_atomic_long_cast(zval *zobject);
ThreadResource *php_swoole_thread_barrier_cast(zval *zobject);

void php_swoole_thread_arraylist_create(zval *return_value, ThreadResource *resource);
void php_swoole_thread_map_create(zval *return_value, ThreadResource *resource);
void php_swoole_thread_queue_create(zval *return_value, ThreadResource *resource);
void php_swoole_thread_lock_create(zval *return_value, ThreadResource *resource);
void php_swoole_thread_atomic_create(zval *return_value, ThreadResource *resource);
void php_swoole_thread_atomic_long_create(zval *return_value, ThreadResource *resource);
void php_swoole_thread_barrier_create(zval *return_value, ThreadResource *resource);

int php_swoole_thread_stream_cast(zval *zstream);
void php_swoole_thread_stream_create(zval *return_value, zend_long sockfd);

int php_swoole_thread_co_socket_cast(zval *zstream, swSocketType *type);
void php_swoole_thread_co_socket_create(zval *return_value, zend_long sockfd, swSocketType type);

#define EMSG_NO_RESOURCE "resource not found"
#define ECODE_NO_RESOURCE -2

enum {
    IS_ARRAYLIST = 80,
    IS_QUEUE = 81,
    IS_LOCK = 82,
    IS_MAP = 83,
    IS_BARRIER = 84,
    IS_ATOMIC = 85,
    IS_ATOMIC_LONG = 86,
    IS_PHP_SOCKET = 96,
    IS_CO_SOCKET = 97,
    IS_STREAM_SOCKET = 98,
    IS_SERIALIZED_OBJECT = 99,
};

class ThreadResource {
    sw_atomic_t ref_count;

  public:
    ThreadResource() {
        ref_count = 1;
    }

    void add_ref() {
        sw_atomic_add_fetch(&ref_count, 1);
    }

    void del_ref() {
        if (sw_atomic_sub_fetch(&ref_count, 1) == 0) {
            delete this;
        }
    }

  protected:
    virtual ~ThreadResource() {}
};

struct ArrayItem {
    uint32_t type = IS_UNDEF;
    zend_string *key = nullptr;
    union {
        zend_string *str;
        zend_long lval;
        double dval;
        struct {
            int fd;
            swSocketType type;
        } socket;
        zend_string *serialized_object;
        ThreadResource *resource;
    } value;

    ArrayItem(zval *zvalue) {
        value = {};
        store(zvalue);
    }

    void setKey(zend::String &_key) {
        key = zend_string_init(_key.val(), _key.len(), 1);
    }

    void setKey(zend_string *_key) {
        key = zend_string_init(ZSTR_VAL(_key), ZSTR_LEN(_key), 1);
    }

    void store(zval *zvalue);
    void fetch(zval *return_value);
    void release();
    bool equals(zval *zvalue);

    ~ArrayItem() {
        if (value.str) {
            release();
        }
        if (key) {
            zend_string_release(key);
        }
    }
};

class ZendArray : public ThreadResource {
  protected:
    swoole::RWLock lock_;
    zend_array ht;

    static void item_dtor(zval *pDest) {
        ArrayItem *item = (ArrayItem *) Z_PTR_P(pDest);
        delete item;
    }

  public:
    ZendArray() : ThreadResource(), lock_(0) {
        zend_hash_init(&ht, 0, NULL, item_dtor, 1);
    }

    ~ZendArray() override {
        zend_hash_destroy(&ht);
    }

    void clean() {
        lock_.lock();
        zend_hash_clean(&ht);
        lock_.unlock();
    }

    void append(zval *zvalue);

    void add(zend_string *skey, zval *zvalue) {
        auto item = new ArrayItem(zvalue);
        item->setKey(skey);
        zend_hash_add_ptr(&ht, item->key, item);
    }

    void add(zend::String &skey, zval *zvalue) {
        auto item = new ArrayItem(zvalue);
        item->setKey(skey);
        zend_hash_add_ptr(&ht, item->key, item);
    }

    void add(zend_long index, zval *zvalue) {
        auto item = new ArrayItem(zvalue);
        zend_hash_index_add_ptr(&ht, index, item);
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
    void intkey_incr(zend_long index, zval *zvalue, zval *return_value);
    void strkey_decr(zval *zkey, zval *zvalue, zval *return_value);
    void intkey_decr(zend_long index, zval *zvalue, zval *return_value);
    bool index_incr(zval *zkey, zval *zvalue, zval *return_value);
    bool index_decr(zval *zkey, zval *zvalue, zval *return_value);

    void strkey_add(zval *zkey, zval *zvalue, zval *return_value);
    void intkey_add(zend_long index, zval *zvalue, zval *return_value);
    void strkey_update(zval *zkey, zval *zvalue, zval *return_value);
    void intkey_update(zend_long index, zval *zvalue, zval *return_value);

    void count(zval *return_value) {
        lock_.lock_rd();
        RETVAL_LONG(zend_hash_num_elements(&ht));
        lock_.unlock();
    }

    void keys(zval *return_value);
    void values(zval *return_value);
    void to_array(zval *return_value);
    void find(zval *search, zval *return_value);

    void intkey_offsetGet(zend_long index, zval *return_value) {
        lock_.lock_rd();
        ArrayItem *item = (ArrayItem *) zend_hash_index_find_ptr(&ht, index);
        if (item) {
            item->fetch(return_value);
        }
        lock_.unlock();
    }

    void intkey_offsetExists(zend_long index, zval *return_value) {
        lock_.lock_rd();
        RETVAL_BOOL(intkey_exists(index));
        lock_.unlock();
    }

    void intkey_offsetUnset(zend_long index) {
        lock_.lock();
        zend_hash_index_del(&ht, index);
        lock_.unlock();
    }

    void intkey_offsetSet(zend_long index, zval *zvalue) {
        auto item = new ArrayItem(zvalue);
        lock_.lock();
        zend_hash_index_update_ptr(&ht, index, item);
        lock_.unlock();
    }

    bool index_offsetGet(zend_long index, zval *return_value);
    bool index_offsetSet(zend_long index, zval *zvalue);
    void index_offsetUnset(zend_long index);
    void index_offsetExists(zend_long index, zval *return_value);

    static void incr_update(ArrayItem *item, zval *zvalue, zval *return_value);
    static ArrayItem *incr_create(zval *zvalue, zval *return_value);
    static ZendArray *from(zend_array *ht);
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

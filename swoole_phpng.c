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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
 */
#include "php_swoole.h"

inline int Z_BVAL_P(zval *v) {
    if (Z_TYPE_P(v) == IS_TRUE) {
        return 1;
    } else {
        return 0;
    }
}

inline int sw_add_assoc_stringl_ex(zval *arg, const char *key, size_t key_len, char *str, size_t length, int duplicate) {
    return add_assoc_stringl_ex(arg, key, key_len, str, length);
}

inline char * sw_php_format_date(char *format, size_t format_len, time_t ts, int localtime) {
    zend_string *time = php_format_date(format, format_len, ts, localtime);

    char *return_str = (char*) emalloc(time->len);
    memcpy(return_str, time->val, time->len);
    zend_string_release(time);
    return return_str;
}

inline char * sw_php_url_encode(char *value, size_t value_len, int* exten) {
    zend_string *str = php_url_encode(value, value_len);
    *exten = str->len;

    char *return_str = (char*) emalloc(str->len);
    memcpy(return_str, str->val, str->len);
    zend_string_release(str);

    return return_str;
}

inline zval * sw_zend_read_property(zend_class_entry *class_ptr, zval *obj, char *s, int len, int what) {
    zval rv;
    return zend_read_property(class_ptr, obj, s, len, 0, &rv TSRMLS_CC);
}

inline int sw_zend_is_callable(zval *cb, int a, char **name) {
    zend_string *key;
    int ret = zend_is_callable(cb, a, &key);
    char * tmp = (char *)emalloc(key->len);
    memcpy(tmp, key->val, key->len);
    *name = tmp;
    return ret;
}

inline int sw_zend_hash_del(HashTable *ht, char *k, int len) {
    zval key;
    ZVAL_STRING(&key, k);

    return zend_hash_del(ht, Z_STR(key));

}

inline int sw_zend_hash_add(HashTable *ht, char *k, int len, void *pData, int datasize, void **pDest) {
    zval key;
    ZVAL_STRING(&key, k);
    zval **real_p = pData;

    return zend_hash_add(ht, Z_STR(key), *real_p) ? SUCCESS : FAILURE;
}

inline int sw_zend_hash_index_update(HashTable *ht, int key, void *pData, int datasize, void **pDest) {
    zval **real_p = pData;
    return zend_hash_index_update(ht, key, *real_p) ? SUCCESS : FAILURE;
}

inline int sw_zend_hash_update(HashTable *ht, char *k, int len, void * val, int size, void *ptr) {
    zval key;
    ZVAL_STRING(&key, k);

    return zend_hash_update(ht, Z_STR(key), val) ? SUCCESS : FAILURE;
}

inline int wrapper_zend_hash_get_current_key(HashTable *ht, char **key, uint *idx, ulong *num) {
    zval str_key;
    ZVAL_STRING(&str_key, *key);
    int type = zend_hash_get_current_key(ht, &Z_STR(str_key), (zend_ulong*) num);
    *key = Z_STR(str_key)->val;
    return type;
}

inline int sw_zend_hash_find(HashTable *ht, char *k, int len, void **v) {
    //    char _key[128];
    //    zend_string *key;
    //
    //    if (sizeof (zend_string) + len > sizeof (_key)) {
    //        key = emalloc(sizeof (zend_string) + len);
    //    } else {
    //        key = _key;
    //    }
    //
    //    key->len = len;
    //    memcpy(key->val, k, len);
    //    key->val[len] = 0;
#if PHP_MAJOR_VERSION < 7
    zval **tmp = NULL;
      if(zend_hash_find(ht, k,len, (void **) &tmp) == SUCCESS){
          *v = *tmp;
          return SUCCESS;
      }else{
          *v = NULL;
          return FAILURE;
      }
#else
      zval key;
        ZVAL_STRING(&key, k);

        zval *value = zend_hash_find(ht, Z_STR(key));

        if (value == NULL) {
            return FAILURE;
        } else {
            *v = (void *)value;
            v = (void *)value;
            return SUCCESS;
        }
#endif

}


inline int sw_zend_hash_exists(HashTable *ht, char *k, int len) {
    zval **tmp = NULL;
      if(zend_hash_find(ht, k,len, (void **) &tmp) == SUCCESS){
          return SUCCESS;
      }else{
          return FAILURE;
      }
}

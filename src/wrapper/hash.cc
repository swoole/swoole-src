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

extern "C"
{
#include <ext/hash/php_hash.h>
}

using namespace std;

namespace php
{

static struct HashAlgo
{
    const php_hash_ops *md5 = nullptr;
    const php_hash_ops *sha1 = nullptr;
    const php_hash_ops *crc32 = nullptr;
    void *context = nullptr;
    size_t context_size = 0;
    uchar *key = nullptr;
    size_t key_size = 0;
} hash_algos;

static String doHash(const php_hash_ops *ops, String &data, bool raw_output)
{
    if (hash_algos.context_size < ops->context_size)
    {
        hash_algos.context_size = ops->context_size;
        hash_algos.context = malloc(hash_algos.context_size);
    }

    void *context = hash_algos.context;
    ops->hash_init(context);
    ops->hash_update(context, (unsigned char *) data.c_str(), data.length());

    zend_string *digest = zend_string_alloc(ops->digest_size, 0);
    ops->hash_final((unsigned char *) ZSTR_VAL(digest), context);

    if (raw_output)
    {
        ZSTR_VAL(digest)[ops->digest_size] = 0;
        return digest;
    }
    else
    {
        zend_string *hex_digest = zend_string_safe_alloc(ops->digest_size, 2, 0, 0);
        php_hash_bin2hex(ZSTR_VAL(hex_digest), (unsigned char *) ZSTR_VAL(digest), ops->digest_size);
        ZSTR_VAL(hex_digest)[2 * ops->digest_size] = 0;
        zend_string_release(digest);
        return hex_digest;
    }
}

String md5(String data, bool raw_output)
{
    if (hash_algos.md5 == nullptr)
    {
        hash_algos.md5 = php_hash_fetch_ops(ZEND_STRL("md5"));
    }
    return doHash(hash_algos.md5, data, raw_output);
}

String sha1(String data, bool raw_output)
{
    if (hash_algos.sha1 == nullptr)
    {
        hash_algos.sha1 = php_hash_fetch_ops(ZEND_STRL("sha1"));
    }
    return doHash(hash_algos.sha1, data, raw_output);
}

String crc32(String data, bool raw_output)
{
    if (hash_algos.crc32 == nullptr)
    {
        hash_algos.crc32 = php_hash_fetch_ops(ZEND_STRL("crc32"));
    }
    return doHash(hash_algos.crc32, data, raw_output);
}

String hash(String algo, String data, bool raw_output)
{
    const php_hash_ops *ops = php_hash_fetch_ops(algo.c_str(), algo.length());
    if (!ops)
    {
        return "";
    }
    return doHash(ops, data, raw_output);
}

static inline void php_hash_string_xor_char(uchar *out, const uchar *in, const uchar xor_with, const int length)
{
    int i;
    for (i = 0; i < length; i++)
    {
        out[i] = in[i] ^ xor_with;
    }
}

static inline void php_hash_hmac_prep_key(uchar *K, const php_hash_ops *ops, void *context, const uchar *key, const size_t key_len)
{
    memset(K, 0, ops->block_size);
    if (key_len > ops->block_size)
    {
        /* Reduce the key first */
        ops->hash_init(context);
        ops->hash_update(context, key, key_len);
        ops->hash_final(K, context);
    }
    else
    {
        memcpy(K, key, key_len);
    }
    /* XOR the key with 0x36 to get the ipad) */
    php_hash_string_xor_char(K, K, 0x36, ops->block_size);
}

String hash_hmac(String algo, String data, String key, bool raw_output)
{
    const php_hash_ops *ops = php_hash_fetch_ops(algo.c_str(), algo.length());
    if (!ops)
    {
        return "";
    }
    if (hash_algos.context_size < ops->context_size)
    {
        hash_algos.context_size = ops->context_size;
        hash_algos.context = malloc(hash_algos.context_size);
    }
    if (hash_algos.key_size < ops->block_size)
    {
        hash_algos.key_size = ops->block_size;
        hash_algos.key = (uchar *) malloc(hash_algos.key_size);
    }

    void *context = hash_algos.context;
    uchar *_key = hash_algos.key;
    zend_string *digest = zend_string_alloc(ops->digest_size, 0);

    php_hash_hmac_prep_key((uchar *) _key, ops, context, (uchar *) key.c_str(), key.length());

    ops->hash_init(context);
    ops->hash_update(context, _key, ops->block_size);
    ops->hash_update(context, (uchar *) data.c_str(), data.length());
    ops->hash_final((uchar *) ZSTR_VAL(digest), context);

    php_hash_string_xor_char(_key, _key, 0x6A, ops->block_size);

    ops->hash_init(context);
    ops->hash_update(context, _key, ops->block_size);
    ops->hash_update(context, (uchar *) ZSTR_VAL(digest), ops->digest_size);
    ops->hash_final((uchar *) ZSTR_VAL(digest), context);

    if (raw_output)
    {
        ZSTR_VAL(digest)[ops->digest_size] = 0;
        return digest;
    }
    else
    {
        zend_string *hex_digest = zend_string_safe_alloc(ops->digest_size, 2, 0, 0);
        php_hash_bin2hex(ZSTR_VAL(hex_digest), (uchar *) ZSTR_VAL(digest), ops->digest_size);
        ZSTR_VAL(hex_digest)[2 * ops->digest_size] = 0;
        zend_string_release(digest);
        return hex_digest;
    }
}

}

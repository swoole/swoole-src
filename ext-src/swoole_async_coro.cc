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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "php_swoole_cxx.h"
#include "swoole_socket.h"

#include <string>
#include <vector>
#include <unordered_map>

using std::string;
using std::vector;
using swoole::Coroutine;
using swoole::PHPCoroutine;
using swoole::Timer;
using swoole::coroutine::Socket;

struct DNSCacheEntity {
    char address[INET6_ADDRSTRLEN];
    time_t update_time;
};

static std::unordered_map<std::string, DNSCacheEntity *> request_cache_map;

void php_swoole_async_coro_rshutdown() {
    for (auto i = request_cache_map.begin(); i != request_cache_map.end(); i++) {
        efree(i->second);
    }
}

void php_swoole_set_aio_option(HashTable *vht) {
    zval *ztmp;
    /* AIO */
   if (php_swoole_array_get_value(vht, "aio_core_worker_num", ztmp)) {
       zend_long v = zval_get_long(ztmp);
       v = SW_MAX(1, SW_MIN(v, UINT32_MAX));
       SwooleG.aio_core_worker_num = v;
   }
   if (php_swoole_array_get_value(vht, "aio_worker_num", ztmp)) {
       zend_long v = zval_get_long(ztmp);
       v = SW_MAX(1, SW_MIN(v, UINT32_MAX));
       SwooleG.aio_worker_num = v;
   }
   if (php_swoole_array_get_value(vht, "aio_max_wait_time", ztmp)) {
       SwooleG.aio_max_wait_time = zval_get_double(ztmp);
   }
   if (php_swoole_array_get_value(vht, "aio_max_idle_time", ztmp)) {
       SwooleG.aio_max_idle_time = zval_get_double(ztmp);
   }
}

PHP_FUNCTION(swoole_async_set) {
    if (sw_reactor()) {
        php_swoole_fatal_error(E_ERROR, "eventLoop has already been created. unable to change settings");
        RETURN_FALSE;
    }

    zval *zset = nullptr;
    HashTable *vht;
    zval *ztmp;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);

    php_swoole_set_global_option(vht);
    php_swoole_set_aio_option(vht);

    if (php_swoole_array_get_value(vht, "enable_signalfd", ztmp)) {
        SwooleG.enable_signalfd = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "wait_signal", ztmp)) {
        SwooleG.wait_signal = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "dns_cache_refresh_time", ztmp)) {
        SwooleG.dns_cache_refresh_time = zval_get_double(ztmp);
    }
    if (php_swoole_array_get_value(vht, "thread_num", ztmp) ||
        php_swoole_array_get_value(vht, "min_thread_num", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        v = SW_MAX(1, SW_MIN(v, UINT32_MAX));
        SwooleG.aio_core_worker_num = v;
    }
    if (php_swoole_array_get_value(vht, "max_thread_num", ztmp)) {
        zend_long v = zval_get_long(ztmp);
        v = SW_MAX(1, SW_MIN(v, UINT32_MAX));
        SwooleG.aio_worker_num = v;
    }
    if (php_swoole_array_get_value(vht, "socket_dontwait", ztmp)) {
        SwooleG.socket_dontwait = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "dns_lookup_random", ztmp)) {
        SwooleG.dns_lookup_random = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "use_async_resolver", ztmp)) {
        SwooleG.use_async_resolver = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "enable_coroutine", ztmp)) {
        SWOOLE_G(enable_coroutine) = zval_is_true(ztmp);
    }
}

PHP_FUNCTION(swoole_async_dns_lookup_coro) {
    Coroutine::get_current_safe();

    zval *domain;
    long type = AF_INET;
    double timeout = swoole::network::Socket::default_dns_timeout;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|dl", &domain, &timeout, &type) == FAILURE) {
        RETURN_FALSE;
    }

    if (Z_TYPE_P(domain) != IS_STRING) {
        php_swoole_fatal_error(E_WARNING, "invalid domain name");
        RETURN_FALSE;
    }

    if (Z_STRLEN_P(domain) == 0) {
        php_swoole_fatal_error(E_WARNING, "domain name empty");
        RETURN_FALSE;
    }

    // find cache
    std::string key(Z_STRVAL_P(domain), Z_STRLEN_P(domain));
    DNSCacheEntity *cache;

    if (request_cache_map.find(key) != request_cache_map.end()) {
        cache = request_cache_map[key];
        if (cache->update_time > Timer::get_absolute_msec()) {
            RETURN_STRING(cache->address);
        }
    }

    php_swoole_check_reactor();

    vector<string> result = swoole::coroutine::dns_lookup(Z_STRVAL_P(domain), type, timeout);
    if (result.empty()) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        RETURN_FALSE;
    }

    if (SwooleG.dns_lookup_random) {
        RETVAL_STRING(result[rand() % result.size()].c_str());
    } else {
        RETVAL_STRING(result[0].c_str());
    }

    auto cache_iterator = request_cache_map.find(key);
    if (cache_iterator == request_cache_map.end()) {
        cache = (DNSCacheEntity *) emalloc(sizeof(DNSCacheEntity));
        request_cache_map[key] = cache;
    } else {
        cache = cache_iterator->second;
    }
    memcpy(cache->address, Z_STRVAL_P(return_value), Z_STRLEN_P(return_value));
    cache->address[Z_STRLEN_P(return_value)] = '\0';
    cache->update_time = Timer::get_absolute_msec() + (int64_t)(SwooleG.dns_cache_refresh_time * 1000);
}

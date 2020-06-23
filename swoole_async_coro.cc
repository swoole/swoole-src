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

#include "php_swoole_cxx.h"
#include "php_streams.h"
#include "php_network.h"

#include "ext/standard/file.h"
#include "ext/standard/basic_functions.h"

#include <string>
#include <vector>
#include <unordered_map>

using swoole::PHPCoroutine;
using swoole::Coroutine;
using swoole::coroutine::Socket;
using std::string;
using std::vector;

struct dns_cache
{
    char address[16];
    time_t update_time;
};

struct process_stream
{
    zval *callback;
    pid_t pid;
    int fd;
    swString *buffer;
};

static std::unordered_map<std::string, dns_cache*> request_cache_map;

void php_swoole_async_coro_rshutdown()
{
    for (auto i = request_cache_map.begin(); i != request_cache_map.end(); i++)
    {
        efree(i->second);
    }
}

PHP_FUNCTION(swoole_async_set)
{
    if (SwooleTG.reactor)
    {
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

    if (php_swoole_array_get_value(vht, "enable_signalfd", ztmp))
    {
        SwooleG.enable_signalfd = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "wait_signal", ztmp))
    {
        SwooleG.wait_signal = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "dns_cache_refresh_time", ztmp))
    {
          SwooleG.dns_cache_refresh_time = zval_get_double(ztmp);
    }
    if (php_swoole_array_get_value(vht, "socket_buffer_size", ztmp))
    {
        SwooleG.socket_buffer_size = zval_get_long(ztmp);
        if (SwooleG.socket_buffer_size <= 0 || SwooleG.socket_buffer_size > INT_MAX)
        {
            SwooleG.socket_buffer_size = INT_MAX;
        }
    }
    if (php_swoole_array_get_value(vht, "thread_num", ztmp) || php_swoole_array_get_value(vht, "min_thread_num", ztmp))
    {
        zend_long v = zval_get_long(ztmp);
        v = SW_MAX(1, SW_MIN(v, UINT32_MAX));
        SwooleG.aio_core_worker_num = v;
    }
    if (php_swoole_array_get_value(vht, "max_thread_num", ztmp))
    {
        zend_long v = zval_get_long(ztmp);
        v = SW_MAX(1, SW_MIN(v, UINT32_MAX));
        SwooleG.aio_worker_num= v;
    }
    if (php_swoole_array_get_value(vht, "socket_dontwait", ztmp))
    {
        SwooleG.socket_dontwait = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "dns_lookup_random", ztmp))
    {
        SwooleG.dns_lookup_random = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "use_async_resolver", ztmp))
    {
        SwooleG.use_async_resolver = zval_is_true(ztmp);
    }
    if (php_swoole_array_get_value(vht, "enable_coroutine", ztmp))
    {
        SwooleG.enable_coroutine = zval_is_true(ztmp);
    }
}

PHP_FUNCTION(swoole_async_dns_lookup_coro)
{
    Coroutine::get_current_safe();

    zval *domain;
    double timeout = Socket::default_dns_timeout;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|d", &domain, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (Z_TYPE_P(domain) != IS_STRING)
    {
        php_swoole_fatal_error(E_WARNING, "invalid domain name");
        RETURN_FALSE;
    }

    if (Z_STRLEN_P(domain) == 0)
    {
        php_swoole_fatal_error(E_WARNING, "domain name empty");
        RETURN_FALSE;
    }

    //find cache
    std::string key(Z_STRVAL_P(domain), Z_STRLEN_P(domain));
    dns_cache *cache;

    if (request_cache_map.find(key) != request_cache_map.end())
    {
        cache = request_cache_map[key];
        if (cache->update_time > swTimer_get_absolute_msec())
        {
            RETURN_STRING(cache->address);
        }
    }

    php_swoole_check_reactor();

    vector<string> result = swoole::coroutine::dns_lookup(Z_STRVAL_P(domain), timeout);
    if (result.empty())
    {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        RETURN_FALSE;
    }

    if (SwooleG.dns_lookup_random)
    {
        RETVAL_STRING(result[rand() % result.size()].c_str());
    }
    else
    {
        RETVAL_STRING(result[0].c_str());
    }

    auto cache_iterator = request_cache_map.find(key);
    if (cache_iterator == request_cache_map.end())
    {
        cache = (dns_cache *) emalloc(sizeof(dns_cache));
        sw_memset_zero(cache, sizeof(dns_cache));
        request_cache_map[key] = cache;
    }
    else
    {
        cache = cache_iterator->second;
    }
    memcpy(cache->address, Z_STRVAL_P(return_value), Z_STRLEN_P(return_value));
    cache->address[Z_STRLEN_P(return_value)] = '\0';
    cache->update_time = swTimer_get_absolute_msec() + (int64_t) (SwooleG.dns_cache_refresh_time * 1000);
}

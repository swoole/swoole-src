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

#ifdef SW_COROUTINE
#include "swoole_coroutine.h"
#include "ext/standard/basic_functions.h"
#endif

#include <string>
#include <unordered_map>

using namespace swoole;

typedef struct
{
    zval _callback;
    zval _filename;
    zval *callback;
    zval *filename;
    uint32_t *refcount;
    off_t offset;
    uint16_t type;
    uint8_t once;
    char *content;
    uint32_t length;
} file_request;

typedef struct
{
    zval _callback;
    zval _domain;
    zval *callback;
    zval *domain;
    php_coro_context *context;
    uint8_t useless;
    swTimer_node *timer;
} dns_request;

typedef struct
{
    char address[16];
    time_t update_time;
} dns_cache;

typedef struct
{
    zval *callback;
    pid_t pid;
    int fd;
    swString *buffer;
} process_stream;

#ifdef SW_COROUTINE
static void coro_onDNSCompleted(char *domain, swDNSResolver_result *result, void *data);
static void dns_timeout_coro(swTimer *timer, swTimer_node *tnode);
#endif

static std::unordered_map<std::string, dns_cache*> request_cache_map;

void swoole_async_coro_init(int module_number)
{
    bzero(&SwooleAIO, sizeof(SwooleAIO));
    SwooleAIO.min_thread_count = SW_AIO_THREAD_MIN_NUM;
    SwooleAIO.max_thread_count = SW_AIO_THREAD_MAX_NUM;
}

void swoole_async_coro_shutdown()
{
    for(auto i = request_cache_map.begin(); i != request_cache_map.end(); i++)
    {
        efree(i->second);
    }
}

static void coro_onDNSCompleted(char *domain, swDNSResolver_result *result, void *data)
{
    dns_request *req = (dns_request *) data;
    zval *retval = NULL;

    zval zaddress;
    char *address;
    if (result->num > 0)
    {
        if (SwooleG.dns_lookup_random)
        {
            address = result->hosts[rand() % result->num].address;
        }
        else
        {
            address = result->hosts[0].address;
        }

        ZVAL_STRING(&zaddress, address);
    }
    else
    {
        ZVAL_STRING(&zaddress, "");
    }

    std::string key(Z_STRVAL_P(req->domain), Z_STRLEN_P(req->domain));
    dns_cache *cache;
    auto cache_iterator = request_cache_map.find(key);
    if (cache_iterator == request_cache_map.end())
    {
        cache = (dns_cache *) emalloc(sizeof(dns_cache));
        bzero(cache, sizeof(dns_cache));
        request_cache_map[key] = cache;
    }
    else
    {
        cache = cache_iterator->second;
    }

    memcpy(cache->address, Z_STRVAL(zaddress), Z_STRLEN(zaddress));
    cache->address[Z_STRLEN(zaddress)] = '\0';

    cache->update_time = swTimer_get_absolute_msec() + (int64_t) (SwooleG.dns_cache_refresh_time * 1000);

    //timeout
    if (req->timer)
    {
        swTimer_del(&SwooleG.timer, req->timer);
        req->timer = NULL;
    }
    if (req->useless)
    {
        efree(req);
        return;
    }

    int ret = PHPCoroutine::resume_m(req->context, &zaddress, retval);
    if (ret > 0)
    {
        goto free_zdata;
    }

    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    free_zdata:
    zval_ptr_dtor(&zaddress);
    efree(req->context);
    efree(req);
}

static void dns_timeout_coro(swTimer *timer, swTimer_node *tnode)
{
    zval *retval = NULL;
    zval zaddress;
    php_coro_context *cxt = (php_coro_context *) tnode->data;
    dns_request *req = (dns_request *) cxt->coro_params.value.ptr;

    dns_cache *cache = request_cache_map[std::string(Z_STRVAL_P(req->domain), Z_STRLEN_P(req->domain))];
    if (cache != NULL && cache->update_time > swTimer_get_absolute_msec())
    {
        ZVAL_STRING(&zaddress, cache->address);
    }
    else
    {
        ZVAL_STRING(&zaddress, "");
    }

    int ret = PHPCoroutine::resume_m(req->context, &zaddress, retval);
    if (ret > 0)
    {
        goto free_zdata;
    }

    if (retval)
    {
        zval_ptr_dtor(retval);
    }
    free_zdata:
    zval_ptr_dtor(&zaddress);
    efree(req->context);
    req->useless = 1;
}

PHP_FUNCTION(swoole_async_set)
{
    if (SwooleG.main_reactor != NULL)
    {
        swoole_php_fatal_error(E_ERROR, "eventLoop has already been created. unable to change settings");
        RETURN_FALSE;
    }

    zval *zset = NULL;
    HashTable *vht;
    zval *v;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(zset)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    vht = Z_ARRVAL_P(zset);
    if (php_swoole_array_get_value(vht, "enable_signalfd", v))
    {
        SwooleG.enable_signalfd = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "dns_cache_refresh_time", v))
    {
          SwooleG.dns_cache_refresh_time = zval_get_double(v);
    }
    if (php_swoole_array_get_value(vht, "socket_buffer_size", v))
    {
        SwooleG.socket_buffer_size = zval_get_long(v);
        if (SwooleG.socket_buffer_size <= 0 || SwooleG.socket_buffer_size > INT_MAX)
        {
            SwooleG.socket_buffer_size = INT_MAX;
        }
    }
    if (php_swoole_array_get_value(vht, "log_level", v))
    {
        zend_long level = zval_get_long(v);
        SwooleG.log_level = (uint32_t) (level < 0 ? UINT32_MAX : level);
    }
    if (php_swoole_array_get_value(vht, "thread_num", v) || php_swoole_array_get_value(vht, "min_thread_num", v))
    {
        SwooleAIO.max_thread_count = SwooleAIO.min_thread_count = zval_get_long(v);
    }
    if (php_swoole_array_get_value(vht, "max_thread_num", v))
    {
        SwooleAIO.max_thread_count = zval_get_long(v);
    }
    if (php_swoole_array_get_value(vht, "display_errors", v))
    {
        SWOOLE_G(display_errors) = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "socket_dontwait", v))
    {
        SwooleG.socket_dontwait = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "dns_lookup_random", v))
    {
        SwooleG.dns_lookup_random = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "dns_server", v))
    {
        if (SwooleG.dns_server_v4)
        {
            sw_free(SwooleG.dns_server_v4);
        }
        SwooleG.dns_server_v4 = zend::string(v).dup();
    }
    if (php_swoole_array_get_value(vht, "use_async_resolver", v))
    {
        SwooleG.use_async_resolver = zval_is_true(v);
    }
    if (php_swoole_array_get_value(vht, "enable_coroutine", v))
    {
        SwooleG.enable_coroutine = zval_is_true(v);
    }
#if defined(HAVE_REUSEPORT) && defined(HAVE_EPOLL)
    //reuse port
    if (php_swoole_array_get_value(vht, "enable_reuse_port", v))
    {
        if (zval_is_true(v) && swoole_version_compare(SwooleG.uname.release, "3.9.0") >= 0)
        {
            SwooleG.reuse_port = 1;
        }
    }
#endif
}

PHP_FUNCTION(swoole_async_dns_lookup_coro)
{
    zval *domain;
    double timeout = Socket::default_connect_timeout;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z|d", &domain, &timeout) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (Z_TYPE_P(domain) != IS_STRING)
    {
        swoole_php_fatal_error(E_WARNING, "invalid domain name");
        RETURN_FALSE;
    }

    if (Z_STRLEN_P(domain) == 0)
    {
        swoole_php_fatal_error(E_WARNING, "domain name empty");
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

    dns_request *req = (dns_request *) emalloc(sizeof(dns_request));
    req->domain = domain;
    sw_copy_to_stack(req->domain, req->_domain);
    req->useless = 0;

    php_coro_context *context = (php_coro_context *) emalloc(sizeof(php_coro_context));
    context->state = SW_CORO_CONTEXT_RUNNING;
    context->coro_params.value.ptr = (void *) req;
    req->context = context;

    php_swoole_check_reactor();
    int ret = swDNSResolver_request(Z_STRVAL_P(domain), coro_onDNSCompleted, (void *) req);
    if (ret == SW_ERR)
    {
        SW_CHECK_RETURN(ret);
    }
    //add timeout
    req->timer = swTimer_add(&SwooleG.timer, (long) (timeout * 1000), 0, context, dns_timeout_coro);
    if (req->timer)
    {
        context->state = SW_CORO_CONTEXT_IN_DELAYED_TIMEOUT_LIST;
    }
    PHPCoroutine::yield_m(return_value, context);
}

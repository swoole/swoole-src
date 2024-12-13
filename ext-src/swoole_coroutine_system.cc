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

#include "php_swoole_coroutine_system.h"

#include "ext/standard/file.h"
#include <sys/file.h>

#include <string>

using swoole::Coroutine;
using swoole::Event;
using swoole::PHPCoroutine;
using swoole::Reactor;
using swoole::String;
using swoole::TimerNode;
using swoole::coroutine::Socket;
using swoole::coroutine::System;

static zend_class_entry *swoole_coroutine_system_ce;

// clang-format off
static const zend_function_entry swoole_coroutine_system_methods[] =
{
    ZEND_FENTRY(gethostbyname,      ZEND_FN(swoole_coroutine_gethostbyname), arginfo_class_Swoole_Coroutine_System_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(dnsLookup,          ZEND_FN(swoole_async_dns_lookup_coro),   arginfo_class_Swoole_Coroutine_System_dnsLookup,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, exec,                                    arginfo_class_Swoole_Coroutine_System_exec,          ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, sleep,                                   arginfo_class_Swoole_Coroutine_System_sleep,         ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, getaddrinfo,                             arginfo_class_Swoole_Coroutine_System_getaddrinfo,   ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, statvfs,                                 arginfo_class_Swoole_Coroutine_System_statvfs,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, readFile,                                arginfo_class_Swoole_Coroutine_System_readFile,      ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, writeFile,                               arginfo_class_Swoole_Coroutine_System_writeFile,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, wait,                                    arginfo_class_Swoole_Coroutine_System_wait,          ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitPid,                                 arginfo_class_Swoole_Coroutine_System_waitPid,       ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitSignal,                              arginfo_class_Swoole_Coroutine_System_waitSignal,    ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitEvent,                               arginfo_class_Swoole_Coroutine_System_waitEvent,     ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

// clang-format on

void php_swoole_coroutine_system_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_BASE(
        swoole_coroutine_system, "Swoole\\Coroutine\\System", "Co\\System", swoole_coroutine_system_methods, nullptr);
    SW_SET_CLASS_CREATE(swoole_coroutine_system, sw_zend_create_object_deny);
}

PHP_METHOD(swoole_coroutine_system, sleep) {
    double seconds;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_DOUBLE(seconds)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (UNEXPECTED(seconds < SW_TIMER_MIN_SEC)) {
        php_swoole_fatal_error(E_WARNING, "Timer must be greater than or equal to " ZEND_TOSTR(SW_TIMER_MIN_SEC));
        RETURN_FALSE;
    }
    RETURN_BOOL(System::sleep(seconds) == 0);
}

PHP_METHOD(swoole_coroutine_system, readFile) {
    char *filename;
    size_t l_filename;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(filename, l_filename)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    auto result = System::read_file(filename, flags & LOCK_EX);
    if (result == nullptr) {
        RETURN_FALSE;
    } else {
        RETVAL_STRINGL(result->str, result->length);
    }
}

PHP_METHOD(swoole_coroutine_system, writeFile) {
    char *filename;
    size_t l_filename;
    char *data;
    size_t l_data;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
    Z_PARAM_STRING(filename, l_filename)
    Z_PARAM_STRING(data, l_data)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int _flags = 0;
    if (flags & PHP_FILE_APPEND) {
        _flags |= O_APPEND;
    } else {
        _flags |= O_TRUNC;
    }

    ssize_t retval = System::write_file(filename, data, l_data, flags & LOCK_EX, _flags);
    if (retval < 0) {
        RETURN_FALSE;
    } else {
        RETURN_LONG(retval);
    }
}

PHP_FUNCTION(swoole_coroutine_gethostbyname) {
    Coroutine::get_current_safe();

    char *domain_name;
    size_t l_domain_name;
    zend_long family = AF_INET;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(1, 3)
    Z_PARAM_STRING(domain_name, l_domain_name)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(family)
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (l_domain_name == 0) {
        php_swoole_fatal_error(E_WARNING, "domain name is empty");
        RETURN_FALSE;
    }

    if (family != AF_INET && family != AF_INET6) {
        php_swoole_fatal_error(E_WARNING, "unknown protocol family, must be AF_INET or AF_INET6");
        RETURN_FALSE;
    }

    std::string address = System::gethostbyname(std::string(domain_name, l_domain_name), family, timeout);
    if (address.empty()) {
        RETURN_FALSE;
    } else {
        RETURN_STRINGL(address.c_str(), address.length());
    }
}

PHP_FUNCTION(swoole_clear_dns_cache) {
    System::clear_dns_cache();
}

PHP_METHOD(swoole_coroutine_system, getaddrinfo) {
    char *hostname;
    size_t l_hostname;
    zend_long family = AF_INET;
    zend_long socktype = SOCK_STREAM;
    zend_long protocol = IPPROTO_TCP;
    char *service = nullptr;
    size_t l_service = 0;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(1, 6)
    Z_PARAM_STRING(hostname, l_hostname)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(family)
    Z_PARAM_LONG(socktype)
    Z_PARAM_LONG(protocol)
    Z_PARAM_STRING(service, l_service)
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (l_hostname == 0) {
        php_swoole_fatal_error(E_WARNING, "hostname is empty");
        RETURN_FALSE;
    }

    if (family != AF_INET && family != AF_INET6) {
        php_swoole_fatal_error(E_WARNING, "unknown protocol family, must be AF_INET or AF_INET6");
        RETURN_FALSE;
    }

    std::string str_service(service ? service : "");
    std::vector<std::string> result = System::getaddrinfo(hostname, family, socktype, protocol, str_service, timeout);

    if (result.empty()) {
        RETURN_FALSE;
    }

    array_init(return_value);
    for (auto i = result.begin(); i != result.end(); i++) {
        add_next_index_stringl(return_value, i->c_str(), i->length());
    }
}

PHP_METHOD(swoole_coroutine_system, statvfs) {
    char *path;
    size_t l_path;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(path, l_path)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    struct statvfs _stat;
    swoole_coroutine_statvfs(path, &_stat);

    array_init(return_value);
    add_assoc_long(return_value, "bsize", _stat.f_bsize);
    add_assoc_long(return_value, "frsize", _stat.f_frsize);
    add_assoc_long(return_value, "blocks", _stat.f_blocks);
    add_assoc_long(return_value, "bfree", _stat.f_bfree);
    add_assoc_long(return_value, "bavail", _stat.f_bavail);
    add_assoc_long(return_value, "files", _stat.f_files);
    add_assoc_long(return_value, "ffree", _stat.f_ffree);
    add_assoc_long(return_value, "favail", _stat.f_favail);
    add_assoc_long(return_value, "fsid", _stat.f_fsid);
    add_assoc_long(return_value, "flag", _stat.f_flag);
    add_assoc_long(return_value, "namemax", _stat.f_namemax);
}

PHP_METHOD(swoole_coroutine_system, exec) {
    char *command;
    size_t command_len;
    zend_bool get_error_stream = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STRING(command, command_len)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(get_error_stream)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int status;
    auto buffer = std::shared_ptr<String>(swoole::make_string(1024, sw_zend_string_allocator()));
    if (!System::exec(command, get_error_stream, buffer, &status)) {
        RETURN_FALSE;
    }

    auto str = zend::fetch_zend_string_by_val(buffer->str);
    buffer->set_null_terminated();
    str->len = buffer->length;
    buffer->release();

    zval zdata;
    ZVAL_STR(&zdata, str);

    array_init(return_value);
    add_assoc_long(return_value, "code", WEXITSTATUS(status));
    add_assoc_long(return_value, "signal", WTERMSIG(status));
    add_assoc_zval(return_value, "output", &zdata);
}

static void swoole_coroutine_system_wait(INTERNAL_FUNCTION_PARAMETERS, pid_t pid, double timeout) {
    int status;

    Coroutine::get_current_safe();

    if (pid < 0) {
        pid = System::wait(&status, timeout);
    } else {
        pid = System::waitpid(pid, &status, 0, timeout);
    }
    if (pid > 0) {
        array_init(return_value);
        add_assoc_long(return_value, "pid", pid);
        add_assoc_long(return_value, "code", WEXITSTATUS(status));
        add_assoc_long(return_value, "signal", WTERMSIG(status));
    } else {
        swoole_set_last_error(errno);
        RETURN_FALSE;
    }
}

PHP_METHOD(swoole_coroutine_system, wait) {
    SW_MUST_BE_MAIN_THREAD();
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_coroutine_system_wait(INTERNAL_FUNCTION_PARAM_PASSTHRU, -1, timeout);
}

PHP_METHOD(swoole_coroutine_system, waitPid) {
    SW_MUST_BE_MAIN_THREAD();
    zend_long pid;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_LONG(pid)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_coroutine_system_wait(INTERNAL_FUNCTION_PARAM_PASSTHRU, pid, timeout);
}

PHP_METHOD(swoole_coroutine_system, waitSignal) {
    SW_MUST_BE_MAIN_THREAD();
    zval *zsignals;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_ZVAL(zsignals)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    std::vector<int> signals;

    if (ZVAL_IS_ARRAY(zsignals)) {
        zval *item;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(zsignals), item) {
            signals.push_back(zval_get_long(item));
        }
        ZEND_HASH_FOREACH_END();
    } else {
        signals.push_back(zval_get_long(zsignals));
    }

    int signo = System::wait_signal(signals, timeout);
    if (signo == -1) {
        if (swoole_get_last_error() == EBUSY) {
            php_swoole_fatal_error(E_WARNING, "Unable to wait signal, async signal listener has been registered");
        } else if (swoole_get_last_error() == EINVAL) {
            php_swoole_fatal_error(E_WARNING, "Invalid signal in the given list");
        }
        errno = swoole_get_last_error();
        RETURN_FALSE;
    }

    RETURN_LONG(signo);
}

PHP_METHOD(swoole_coroutine_system, waitEvent) {
    zval *zfd;
    zend_long events = SW_EVENT_READ;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(1, 3)
    Z_PARAM_ZVAL(zfd)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(events)
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int fd = php_swoole_convert_to_fd(zfd);
    if (fd < 0) {
        php_swoole_fatal_error(E_WARNING, "unknown fd type");
        RETURN_FALSE;
    }

    events = System::wait_event(fd, events, timeout);
    if (events < 0) {
        RETURN_FALSE;
    }

    RETURN_LONG(events);
}

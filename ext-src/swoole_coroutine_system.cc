#include "php_swoole_coroutine_system.h"

#include "ext/standard/file.h"
#include <sys/file.h>

#include <string>

using swoole::TimerNode;
using swoole::Coroutine;
using swoole::PHPCoroutine;
using swoole::Reactor;
using swoole::Event;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using swoole::String;

static zend_class_entry *swoole_coroutine_system_ce;

// clang-format off

static const zend_function_entry swoole_coroutine_system_methods[] =
{
    ZEND_FENTRY(gethostbyname, ZEND_FN(swoole_coroutine_gethostbyname), arginfo_swoole_coroutine_system_gethostbyname, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(dnsLookup, ZEND_FN(swoole_async_dns_lookup_coro), arginfo_swoole_coroutine_system_dnsLookup, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, exec, arginfo_swoole_coroutine_system_exec, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, sleep, arginfo_swoole_coroutine_system_sleep, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, getaddrinfo, arginfo_swoole_coroutine_system_getaddrinfo, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, statvfs, arginfo_swoole_coroutine_system_statvfs, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, readFile, arginfo_swoole_coroutine_system_readFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, writeFile, arginfo_swoole_coroutine_system_writeFile, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, wait, arginfo_swoole_coroutine_system_wait, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitPid, arginfo_swoole_coroutine_system_waitPid, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitSignal, arginfo_swoole_coroutine_system_waitSignal, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_coroutine_system, waitEvent, arginfo_swoole_coroutine_system_waitEvent, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    /* Deprecated file methods */
    PHP_ME(swoole_coroutine_system, fread, arginfo_swoole_coroutine_system_fread, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC | ZEND_ACC_DEPRECATED)
    PHP_ME(swoole_coroutine_system, fwrite, arginfo_swoole_coroutine_system_fwrite, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC | ZEND_ACC_DEPRECATED)
    PHP_ME(swoole_coroutine_system, fgets, arginfo_swoole_coroutine_system_fgets, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC | ZEND_ACC_DEPRECATED)
    PHP_FE_END
};

// clang-format on

void php_swoole_coroutine_system_minit(int module_number) {
    SW_INIT_CLASS_ENTRY_BASE(swoole_coroutine_system,
                             "Swoole\\Coroutine\\System",
                             nullptr,
                             "Co\\System",
                             swoole_coroutine_system_methods,
                             nullptr);
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

static void co_socket_read(int fd, zend_long length, INTERNAL_FUNCTION_PARAMETERS) {
    php_swoole_check_reactor();
    Socket _socket(fd, SW_SOCK_RAW);

    zend_string *buf = zend_string_alloc(length + 1, 0);
    size_t nbytes = length <= 0 ? SW_BUFFER_SIZE_STD : length;
    ssize_t n = _socket.read(ZSTR_VAL(buf), nbytes);
    if (n < 0) {
        ZVAL_FALSE(return_value);
        zend_string_free(buf);
    } else if (n == 0) {
        ZVAL_EMPTY_STRING(return_value);
        zend_string_free(buf);
    } else {
        ZSTR_VAL(buf)[n] = 0;
        ZSTR_LEN(buf) = n;
        ZVAL_STR(return_value, buf);
    }
    _socket.move_fd();
}

static void co_socket_write(int fd, char *str, size_t l_str, INTERNAL_FUNCTION_PARAMETERS) {
    php_swoole_check_reactor();
    Socket _socket(fd, SW_SOCK_RAW);

    ssize_t n = _socket.write(str, l_str);
    if (n < 0) {
        swoole_set_last_error(errno);
        ZVAL_FALSE(return_value);
    } else {
        ZVAL_LONG(return_value, n);
    }
    _socket.move_fd();
}

PHP_METHOD(swoole_coroutine_system, fread) {
    Coroutine::get_current_safe();

    zval *handle;
    zend_long length = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_RESOURCE(handle)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int async;
    int fd = php_swoole_convert_to_fd_ex(handle, &async);
    if (fd < 0) {
        RETURN_FALSE;
    }

    if (async) {
        co_socket_read(fd, length, INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    if (length <= 0) {
        struct stat file_stat;
        if (swoole_coroutine_fstat(fd, &file_stat) < 0) {
            swoole_set_last_error(errno);
            RETURN_FALSE;
        }
        off_t _seek = swoole_coroutine_lseek(fd, 0, SEEK_CUR);
        if (_seek < 0) {
            swoole_set_last_error(errno);
            RETURN_FALSE;
        }
        if (_seek >= file_stat.st_size) {
            length = SW_BUFFER_SIZE_STD;
        } else {
            length = file_stat.st_size - _seek;
        }
    }

    char *buf = (char *) emalloc(length + 1);
    if (!buf) {
        RETURN_FALSE;
    }
    buf[length] = 0;
    int ret = -1;
    swoole_trace("fd=%d, length=%ld", fd, length);
    php_swoole_check_reactor();
    bool async_success = swoole::coroutine::async([&]() {
        while (1) {
            ret = read(fd, buf, length);
            if (ret < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
    });

    if (async_success && ret >= 0) {
        // TODO: Optimization: reduce memory copy
        ZVAL_STRINGL(return_value, buf, ret);
    } else {
        ZVAL_FALSE(return_value);
    }

    efree(buf);
}

PHP_METHOD(swoole_coroutine_system, fgets) {
    Coroutine::get_current_safe();

    zval *handle;
    php_stream *stream;

    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_RESOURCE(handle)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int async;
    int fd = php_swoole_convert_to_fd_ex(handle, &async);
    if (fd < 0) {
        RETURN_FALSE;
    }

    if (async == 1) {
        php_swoole_fatal_error(E_WARNING, "only support file resources");
        RETURN_FALSE;
    }

    php_stream_from_res(stream, Z_RES_P(handle));

    FILE *file;
    if (stream->stdiocast) {
        file = stream->stdiocast;
    } else {
        if (php_stream_cast(stream, PHP_STREAM_AS_STDIO, (void **) &file, 1) != SUCCESS || file == nullptr) {
            RETURN_FALSE;
        }
    }

    if (stream->readbuf == nullptr) {
        stream->readbuflen = stream->chunk_size;
        stream->readbuf = (uchar *) emalloc(stream->chunk_size);
    }

    if (!stream->readbuf) {
        RETURN_FALSE;
    }

    int ret = 0;
    swoole_trace("fd=%d, length=%ld", fd, stream->readbuflen);
    php_swoole_check_reactor();
    bool async_success = swoole::coroutine::async([&]() {
        char *data = fgets((char *) stream->readbuf, stream->readbuflen, file);
        if (data == nullptr) {
            ret = -1;
            stream->eof = 1;
        }
    });

    if (async_success && ret != -1) {
        ZVAL_STRING(return_value, (char *) stream->readbuf);
    } else {
        ZVAL_FALSE(return_value);
    }
}

PHP_METHOD(swoole_coroutine_system, fwrite) {
    Coroutine::get_current_safe();

    zval *handle;
    char *str;
    size_t l_str;
    zend_long length = 0;

    ZEND_PARSE_PARAMETERS_START(2, 3)
    Z_PARAM_RESOURCE(handle)
    Z_PARAM_STRING(str, l_str)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    int async;
    int fd = php_swoole_convert_to_fd_ex(handle, &async);
    if (fd < 0) {
        RETURN_FALSE;
    }

    if (async) {
        co_socket_write(
            fd, str, (length <= 0 || (size_t) length > l_str) ? l_str : length, INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    if (length <= 0 || (size_t) length > l_str) {
        length = l_str;
    }

    char *buf = estrndup(str, length);

    if (!buf) {
        RETURN_FALSE;
    }

    int ret = -1;
    swoole_trace("fd=%d, length=%ld", fd, length);
    php_swoole_check_reactor();
    bool async_success = swoole::coroutine::async([&]() {
        while (1) {
            ret = write(fd, buf, length);
            if (ret < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
    });

    if (async_success && ret >= 0) {
        ZVAL_LONG(return_value, ret);
    } else {
        ZVAL_FALSE(return_value);
    }

    efree(buf);
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

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|ld", &domain_name, &l_domain_name, &family, &timeout) == FAILURE) {
        RETURN_FALSE;
    }

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

    if (zend_parse_parameters(ZEND_NUM_ARGS(),
                              "s|lllsd",
                              &hostname,
                              &l_hostname,
                              &family,
                              &socktype,
                              &protocol,
                              &service,
                              &l_service,
                              &timeout) == FAILURE) {
        RETURN_FALSE;
    }

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

    if (php_swoole_signal_isset_handler(SIGCHLD)) {
        php_swoole_error(E_WARNING, "The signal [SIGCHLD] is registered, cannot execute swoole_coroutine_exec");
        RETURN_FALSE;
    }

    Coroutine::get_current_safe();

    pid_t pid;
    int fd = swoole_shell_exec(command, &pid, get_error_stream);
    if (fd < 0) {
        php_swoole_error(E_WARNING, "Unable to execute '%s'", command);
        RETURN_FALSE;
    }

    String *buffer = new String(1024);
    Socket socket(fd, SW_SOCK_UNIX_STREAM);
    while (1) {
        ssize_t retval = socket.read(buffer->str + buffer->length, buffer->size - buffer->length);
        if (retval > 0) {
            buffer->length += retval;
            if (buffer->length == buffer->size) {
                if (!buffer->extend()) {
                    break;
                }
            }
        } else {
            break;
        }
    }
    socket.close();

    zval zdata;
    if (buffer->length == 0) {
        ZVAL_EMPTY_STRING(&zdata);
    } else {
        ZVAL_STRINGL(&zdata, buffer->str, buffer->length);
    }
    delete buffer;

    int status;
    pid_t _pid = swoole_coroutine_waitpid(pid, &status, 0);
    if (_pid > 0) {
        array_init(return_value);
        add_assoc_long(return_value, "code", WEXITSTATUS(status));
        add_assoc_long(return_value, "signal", WTERMSIG(status));
        add_assoc_zval(return_value, "output", &zdata);
    } else {
        zval_ptr_dtor(&zdata);
        RETVAL_FALSE;
    }
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
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    swoole_coroutine_system_wait(INTERNAL_FUNCTION_PARAM_PASSTHRU, -1, timeout);
}

PHP_METHOD(swoole_coroutine_system, waitPid) {
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
    zend_long signo;
    double timeout = -1;

    ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_LONG(signo)
    Z_PARAM_OPTIONAL
    Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (!System::wait_signal(signo, timeout)) {
        if (swoole_get_last_error() == EBUSY) {
            php_swoole_fatal_error(E_WARNING, "Unable to wait signal, async signal listener has been registered");
        } else if (swoole_get_last_error() == EINVAL) {
            php_swoole_fatal_error(E_WARNING, "Invalid signal [" ZEND_LONG_FMT "]", signo);
        }
        errno = swoole_get_last_error();
        RETURN_FALSE;
    }

    RETURN_TRUE;
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
        RETURN_FALSE;
    }

    events = System::wait_event(fd, events, timeout);
    if (events < 0) {
        RETURN_FALSE;
    }

    RETURN_LONG(events);
}

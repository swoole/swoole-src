/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2016 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Sara Golemon <pollita@php.net>                               |
   +----------------------------------------------------------------------+
*/

#include "php_ssh2.h"
#include "php_swoole_ssh2_hook.h"

void *php_ssh2_zval_from_resource_handle(int handle) {
    zval *val;
    zend_resource *zr;
    ZEND_HASH_FOREACH_VAL(&EG(regular_list), val) {
        zr = Z_RES_P(val);
        if (zr->handle == handle) {
            return val;
        }
    }
    ZEND_HASH_FOREACH_END();
    return NULL;
}

/* **********************
 * channel_stream_ops *
 ********************** */

static ssize_t php_ssh2_channel_stream_write(php_stream *stream, const char *buf, size_t count) {
    php_ssh2_channel_data *abstract = (php_ssh2_channel_data *) stream->abstract;
    ssize_t writestate;
    LIBSSH2_SESSION *session;

    session =
        (LIBSSH2_SESSION *) zend_fetch_resource(abstract->session_rsrc, PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);

#ifdef PHP_SSH2_SESSION_TIMEOUT
    if (abstract->is_blocking) {
        ssh2_set_socket_timeout(session, abstract->timeout);
    }
#endif

    writestate = libssh2_channel_write_ex(abstract->channel, abstract->streamid, buf, count);

#ifdef PHP_SSH2_SESSION_TIMEOUT
    if (abstract->is_blocking) {
        ssh2_set_socket_timeout(session, -1);
    }
#endif

    if (writestate < 0) {
        char *error_msg = NULL;
        if (libssh2_session_last_error(session, &error_msg, NULL, 0) == writestate) {
            php_error_docref(NULL, E_WARNING, "Failure '%s' (%ld)", error_msg, writestate);
        }

        stream->eof = 1;
    }

    return writestate;
}

static ssize_t php_ssh2_channel_stream_read(php_stream *stream, char *buf, size_t count) {
    php_ssh2_channel_data *abstract = (php_ssh2_channel_data *) stream->abstract;
    ssize_t readstate;
    auto session = ssh2_get_session(abstract);

    stream->eof = libssh2_channel_eof(abstract->channel);

#ifdef PHP_SSH2_SESSION_TIMEOUT
    if (abstract->is_blocking) {
        ssh2_set_socket_timeout(session, abstract->timeout);
    }
#endif

    readstate = libssh2_channel_read_ex(abstract->channel, abstract->streamid, buf, count);

#ifdef PHP_SSH2_SESSION_TIMEOUT
    if (abstract->is_blocking) {
        ssh2_set_socket_timeout(session, -1);
    }
#endif

    if (readstate < 0) {
        char *error_msg = NULL;
        if (libssh2_session_last_error(session, &error_msg, NULL, 0) == readstate) {
            php_error_docref(NULL, E_WARNING, "Failure '%s' (%ld)", error_msg, readstate);
        }

        stream->eof = 1;
        readstate = 0;
    }
    return readstate;
}

static int php_ssh2_channel_stream_close(php_stream *stream, int close_handle) {
    php_ssh2_channel_data *abstract = (php_ssh2_channel_data *) stream->abstract;

    if (!abstract->refcount || (--(*(abstract->refcount)) == 0)) {
        /* Last one out, turn off the lights */
        if (abstract->refcount) {
            efree(abstract->refcount);
        }
        auto session = ssh2_get_session(abstract);
        libssh2_channel_eof(abstract->channel);
        libssh2_channel_free(abstract->channel);
        zend_list_delete(abstract->session_rsrc);
    }
    efree(abstract);

    return 0;
}

static int php_ssh2_channel_stream_flush(php_stream *stream) {
    php_ssh2_channel_data *abstract = (php_ssh2_channel_data *) stream->abstract;
    auto session = ssh2_get_session(abstract);

    return libssh2_channel_flush_ex(abstract->channel, abstract->streamid);
}

static int php_ssh2_channel_stream_cast(php_stream *stream, int castas, void **ret) {
    php_ssh2_channel_data *abstract = (php_ssh2_channel_data *) stream->abstract;
    LIBSSH2_SESSION *session;
    php_ssh2_session_data **session_data;

    session =
        (LIBSSH2_SESSION *) zend_fetch_resource(abstract->session_rsrc, PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);
    session_data = (php_ssh2_session_data **) libssh2_session_abstract(session);

    switch (castas) {
    case PHP_STREAM_AS_FD:
    case PHP_STREAM_AS_FD_FOR_SELECT:
    case PHP_STREAM_AS_SOCKETD:
        if (ret) {
            *(php_socket_t *) ret = (*session_data)->socket->get_fd();
        }
        return SUCCESS;
    default:
        return FAILURE;
    }
}

static int php_ssh2_channel_stream_set_option(php_stream *stream, int option, int value, void *ptrparam) {
    php_ssh2_channel_data *abstract = (php_ssh2_channel_data *) stream->abstract;
    auto session = ssh2_get_session(abstract);
    int ret;

    switch (option) {
    case PHP_STREAM_OPTION_BLOCKING: {
        ret = abstract->is_blocking;
        abstract->is_blocking = value;
        return ret;
    }
    case PHP_STREAM_OPTION_META_DATA_API: {
        add_assoc_long((zval *) ptrparam, "exit_status", libssh2_channel_get_exit_status(abstract->channel));
        break;
    }
    case PHP_STREAM_OPTION_READ_TIMEOUT: {
        ret = abstract->timeout;
#ifdef PHP_SSH2_SESSION_TIMEOUT
        struct timeval tv = *(struct timeval *) ptrparam;
        abstract->timeout = tv.tv_sec * 1000 + (tv.tv_usec / 1000);
#else
        php_error_docref(NULL, E_WARNING, "No support for ssh2 stream timeout. Please recompile with libssh2 >= 1.2.9");
#endif
        return ret;
    }
    case PHP_STREAM_OPTION_CHECK_LIVENESS: {
        return stream->eof = libssh2_channel_eof(abstract->channel);
    }
    }

    return -1;
}

php_stream_ops php_ssh2_channel_stream_ops = {
    php_ssh2_channel_stream_write,
    php_ssh2_channel_stream_read,
    php_ssh2_channel_stream_close,
    php_ssh2_channel_stream_flush,
    PHP_SSH2_CHANNEL_STREAM_NAME,
    NULL, /* seek */
    php_ssh2_channel_stream_cast,
    NULL, /* stat */
    php_ssh2_channel_stream_set_option,
};

/* *********************
 * Magic Path Helper *
 ********************* */

/* {{{ php_ssh2_fopen_wraper_parse_path
 * Parse an ssh2.*:// path
 */
php_url *php_ssh2_fopen_wraper_parse_path(const char *path,
                                          const char *type,
                                          php_stream_context *context,
                                          LIBSSH2_SESSION **psession,
                                          zend_resource **presource,
                                          LIBSSH2_SFTP **psftp,
                                          zend_resource **psftp_rsrc) {
    php_ssh2_sftp_data *sftp_data = NULL;
    LIBSSH2_SESSION *session;
    php_url *resource;
    zval *methods = NULL, *callbacks = NULL, zsession, *tmpzval;
    zend_long resource_id;
    const char *h;
    char *username = NULL, *password = NULL, *pubkey_file = NULL, *privkey_file = NULL;
    int username_len = 0, password_len = 0;

    h = strstr(path, "Resource id #");
    if (h) {
        /* Starting with 5.6.28, 7.0.13 need to be clean, else php_url_parse will fail */
        char *tmp = estrdup(path);

        strncpy(tmp + (h - path), h + sizeof("Resource id #") - 1, strlen(tmp) - sizeof("Resource id #"));
        resource = php_url_parse(tmp);
        efree(tmp);
    } else {
        resource = php_url_parse(path);
    }
    if (!resource || !resource->path) {
        return NULL;
    }

    if (strncmp(ZSTR_VAL(resource->scheme), "ssh2.", sizeof("ssh2.") - 1)) {
        /* Not an ssh wrapper */
        php_url_free(resource);
        return NULL;
    }

    if (strcmp(ZSTR_VAL(resource->scheme) + sizeof("ssh2.") - 1, type)) {
        /* Wrong ssh2. wrapper type */
        php_url_free(resource);
        return NULL;
    }

    if (!resource->host) {
        return NULL;
    }

    /*
     * Find resource->path in the path string, then copy the entire string from the original path.
     * This includes ?query#fragment in the path string
     */

    /* Look for a resource ID to reuse a session */
    if (is_numeric_string(ZSTR_VAL(resource->host), ZSTR_LEN(resource->host), &resource_id, NULL, 0) == IS_LONG) {
        php_ssh2_sftp_data *sftp_data;
        zval *zresource;

        if ((zresource = (zval *) php_ssh2_zval_from_resource_handle(resource_id)) == NULL) {
            php_url_free(resource);
            return NULL;
        }

        if (psftp) {
            /* suppress potential warning by passing NULL as resource_type_name */
            sftp_data = (php_ssh2_sftp_data *) zend_fetch_resource(Z_RES_P(zresource), NULL, le_ssh2_sftp);
            if (sftp_data) {
                /* Want the sftp layer */
                Z_ADDREF_P(zresource);
                *psftp_rsrc = Z_RES_P(zresource);
                *psftp = sftp_data->sftp;
                *presource = sftp_data->session_rsrc;
                *psession = sftp_data->session;
                return resource;
            }
        }
        session =
            (LIBSSH2_SESSION *) zend_fetch_resource(Z_RES_P(zresource), PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);
        if (session) {
            if (psftp) {
                /* We need an sftp layer too */
                LIBSSH2_SFTP *sftp = libssh2_sftp_init(session);

                if (!sftp) {
                    php_url_free(resource);
                    return NULL;
                }
                sftp_data = (php_ssh2_sftp_data *) emalloc(sizeof(php_ssh2_sftp_data));
                sftp_data->sftp = sftp;
                sftp_data->session = session;
                sftp_data->session_rsrc = Z_RES_P(zresource);
                Z_ADDREF_P(zresource);
                *psftp_rsrc = zend_register_resource(sftp_data, le_ssh2_sftp);
                *psftp = sftp;
                *presource = Z_RES_P(zresource);
                *psession = session;
                return resource;
            }
            Z_ADDREF_P(zresource);
            *presource = Z_RES_P(zresource);
            *psession = session;
            return resource;
        }
    }

    /* Fallback on finding it in the context */
    if (ZSTR_VAL(resource->host)[0] == 0 && context && psftp &&
        (tmpzval = php_stream_context_get_option(context, "ssh2", "sftp")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_RESOURCE) {
        php_ssh2_sftp_data *sftp_data;
        sftp_data = (php_ssh2_sftp_data *) zend_fetch_resource(Z_RES_P(tmpzval), PHP_SSH2_SFTP_RES_NAME, le_ssh2_sftp);
        if (sftp_data) {
            Z_ADDREF_P(tmpzval);
            *psftp_rsrc = Z_RES_P(tmpzval);
            *psftp = sftp_data->sftp;
            *presource = sftp_data->session_rsrc;
            *psession = sftp_data->session;
            return resource;
        }
    }
    if (ZSTR_VAL(resource->host)[0] == 0 && context &&
        (tmpzval = php_stream_context_get_option(context, "ssh2", "session")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_RESOURCE) {
        session = (LIBSSH2_SESSION *) zend_fetch_resource(Z_RES_P(tmpzval), PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);
        if (session) {
            if (psftp) {
                /* We need an SFTP layer too! */
                LIBSSH2_SFTP *sftp = libssh2_sftp_init(session);
                php_ssh2_sftp_data *sftp_data;

                if (!sftp) {
                    php_url_free(resource);
                    return NULL;
                }
                sftp_data = (php_ssh2_sftp_data *) emalloc(sizeof(php_ssh2_sftp_data));
                sftp_data->sftp = sftp;
                sftp_data->session = session;
                sftp_data->session_rsrc = Z_RES_P(tmpzval);
                Z_ADDREF_P(tmpzval);
                *psftp_rsrc = zend_register_resource(sftp_data, le_ssh2_sftp);
                *psftp = sftp;
                *presource = Z_RES_P(tmpzval);
                *psession = session;
                return resource;
            }
            Z_ADDREF_P(tmpzval);
            *psession = session;
            *presource = Z_RES_P(tmpzval);
            return resource;
        }
    }

    /* Make our own connection then */
    if (!resource->port) {
        resource->port = 22;
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "methods")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_ARRAY) {
        methods = tmpzval;
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "callbacks")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_ARRAY) {
        callbacks = tmpzval;
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "username")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_STRING) {
        username = Z_STRVAL_P(tmpzval);
        username_len = Z_STRLEN_P(tmpzval);
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "password")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_STRING) {
        password = Z_STRVAL_P(tmpzval);
        password_len = Z_STRLEN_P(tmpzval);
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "pubkey_file")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_STRING) {
        pubkey_file = Z_STRVAL_P(tmpzval);
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "privkey_file")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_STRING) {
        privkey_file = Z_STRVAL_P(tmpzval);
    }

    if (resource->user) {
        int len = ZSTR_LEN(resource->user);

        if (len) {
            username = ZSTR_VAL(resource->user);
            username_len = len;
        }
    }

    if (resource->pass) {
        int len = ZSTR_LEN(resource->pass);

        if (len) {
            password = ZSTR_VAL(resource->pass);
            password_len = len;
        }
    }

    if (!username) {
        /* username is a minimum */
        php_url_free(resource);
        return NULL;
    }

    session = php_ssh2_session_connect(ZSTR_VAL(resource->host), resource->port, methods, callbacks);
    if (!session) {
        /* Unable to connect! */
        php_url_free(resource);
        return NULL;
    }

    /* Authenticate */
    if (pubkey_file && privkey_file) {
        if (php_check_open_basedir(pubkey_file) || php_check_open_basedir(privkey_file)) {
            php_url_free(resource);
            return NULL;
        }

        /* Attempt pubkey authentication */
        if (!libssh2_userauth_publickey_fromfile(session, username, pubkey_file, privkey_file, password)) {
            goto session_authed;
        }
    }

    if (password) {
        /* Attempt password authentication */
        if (libssh2_userauth_password_ex(session, username, username_len, password, password_len, NULL) == 0) {
            goto session_authed;
        }
    }

    /* Auth failure */
    php_url_free(resource);
    if (Z_RES(zsession)) {
        zend_list_delete(Z_RES(zsession));
    }
    return NULL;

session_authed:
    ZVAL_RES(&zsession, zend_register_resource(session, le_ssh2_session));

    if (psftp) {
        LIBSSH2_SFTP *sftp;
        zval zsftp{};

        sftp = libssh2_sftp_init(session);
        if (!sftp) {
            php_url_free(resource);
            zend_list_delete(Z_RES(zsession));
            return NULL;
        }

        sftp_data = (php_ssh2_sftp_data *) emalloc(sizeof(php_ssh2_sftp_data));
        sftp_data->session = session;
        sftp_data->sftp = sftp;
        sftp_data->session_rsrc = Z_RES(zsession);

        // TODO Sean-Der
        // ZEND_REGISTER_RESOURCE(sftp_data, le_ssh2_sftp);
        *psftp_rsrc = Z_RES(zsftp);
        *psftp = sftp;
    }

    *presource = Z_RES(zsession);
    *psession = session;

    return resource;
}
/* }}} */

/* *****************
 * Shell Wrapper *
 ***************** */

/* {{{ php_ssh2_shell_open
 * Make a stream from a session
 */
static php_stream *php_ssh2_shell_open(LIBSSH2_SESSION *session,
                                       zend_resource *resource,
                                       const char *term,
                                       int term_len,
                                       zval *environment,
                                       long width,
                                       long height,
                                       long type) {
    LIBSSH2_CHANNEL *channel;
    php_ssh2_channel_data *channel_data;
    php_stream *stream;

    channel = libssh2_channel_open_session(session);
    if (!channel) {
        php_error_docref(NULL, E_WARNING, "Unable to request a channel from remote host");
        return NULL;
    }

    if (environment) {
        zend_string *key;
        int key_type;
        zend_ulong idx;

        for (zend_hash_internal_pointer_reset(HASH_OF(environment));
             (key_type = zend_hash_get_current_key(HASH_OF(environment), &key, &idx)) != HASH_KEY_NON_EXISTENT;
             zend_hash_move_forward(HASH_OF(environment))) {
            if (key_type == HASH_KEY_IS_STRING) {
                zval *value;

                if ((value = zend_hash_get_current_data(HASH_OF(environment))) != NULL) {
                    zval copyval = *value;

                    zval_copy_ctor(&copyval);
                    convert_to_string(&copyval);

                    if (libssh2_channel_setenv_ex(channel, key->val, key->len, Z_STRVAL(copyval), Z_STRLEN(copyval))) {
                        php_error_docref(
                            NULL, E_WARNING, "Failed setting %s=%s on remote end", ZSTR_VAL(key), Z_STRVAL(copyval));
                    }
                    zval_dtor(&copyval);
                }
            } else {
                php_error_docref(NULL, E_NOTICE, "Skipping numeric index in environment array");
            }
        }
    }

    if (type == PHP_SSH2_TERM_UNIT_CHARS) {
        if (libssh2_channel_request_pty_ex(channel, term, term_len, NULL, 0, width, height, 0, 0)) {
            php_error_docref(NULL, E_WARNING, "Failed allocating %s pty at %ldx%ld characters", term, width, height);
            libssh2_channel_free(channel);
            return NULL;
        }
    } else {
        if (libssh2_channel_request_pty_ex(channel, term, term_len, NULL, 0, 0, 0, width, height)) {
            php_error_docref(NULL, E_WARNING, "Failed allocating %s pty at %ldx%ld pixels", term, width, height);
            libssh2_channel_free(channel);
            return NULL;
        }
    }

    if (libssh2_channel_shell(channel)) {
        php_error_docref(NULL, E_WARNING, "Unable to request shell from remote host");
        libssh2_channel_free(channel);
        return NULL;
    }

    /* Turn it into a stream */
    channel_data = (php_ssh2_channel_data *) emalloc(sizeof(php_ssh2_channel_data));
    channel_data->channel = channel;
    channel_data->streamid = 0;
    channel_data->is_blocking = 0;
    channel_data->timeout = 0;
    channel_data->session_rsrc = resource;
    channel_data->refcount = NULL;

    stream = php_stream_alloc(&php_ssh2_channel_stream_ops, channel_data, 0, "r+");

    return stream;
}
/* }}} */

/* {{{ php_ssh2_fopen_wrapper_shell
 * ssh2.shell:// fopen wrapper
 */
static php_stream *php_ssh2_fopen_wrapper_shell(php_stream_wrapper *wrapper,
                                                const char *path,
                                                const char *mode,
                                                int options,
                                                zend_string **opened_path,
                                                php_stream_context *context STREAMS_DC) {
    LIBSSH2_SESSION *session = NULL;
    php_stream *stream;
    zval *tmpzval, *environment = NULL;
    const char *terminal = PHP_SSH2_DEFAULT_TERMINAL;
    zend_long width = PHP_SSH2_DEFAULT_TERM_WIDTH;
    zend_long height = PHP_SSH2_DEFAULT_TERM_HEIGHT;
    zend_long type = PHP_SSH2_DEFAULT_TERM_UNIT;
    zend_resource *rsrc = NULL;
    int terminal_len = sizeof(PHP_SSH2_DEFAULT_TERMINAL) - 1;
    php_url *resource;
    char *s;

    resource = php_ssh2_fopen_wraper_parse_path(path, "shell", context, &session, &rsrc, NULL, NULL);
    if (!resource || !session) {
        return NULL;
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "env")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_ARRAY) {
        environment = tmpzval;
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "term")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_STRING) {
        terminal = Z_STRVAL_P(tmpzval);
        terminal_len = Z_STRLEN_P(tmpzval);
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "term_width")) != NULL) {
        zval copyval;
        copyval = *tmpzval;
        convert_to_long(&copyval);
        width = Z_LVAL_P(&copyval);
        zval_ptr_dtor(&copyval);
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "term_height")) != NULL) {
        zval copyval;
        copyval = *tmpzval;
        convert_to_long(&copyval);
        height = Z_LVAL_P(&copyval);
        zval_ptr_dtor(&copyval);
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "term_units")) != NULL) {
        zval copyval;
        copyval = *tmpzval;
        convert_to_long(&copyval);
        type = Z_LVAL_P(&copyval);
        zval_ptr_dtor(&copyval);
    }

    s = resource->path ? ZSTR_VAL(resource->path) : NULL;

    if (s && s[0] == '/') {
        /* Terminal type encoded into URL overrides context terminal type */
        char *p;

        s++;
        p = strchr(s, '/');
        if (p) {
            if (p - s) {
                terminal = s;
                terminal_len = p - terminal;
                s += terminal_len + 1;
            } else {
                /* "null" terminal given, skip it */
                s++;
            }
        } else {
            int len;

            if ((len = strlen(path + 1))) {
                terminal = s;
                terminal_len = len;
                s += len;
            }
        }
    }

    /* TODO: Accept resolution and environment vars as URL style parameters
     * ssh2.shell://hostorresource/terminal/99x99c?envvar=envval&envvar=envval....
     */
    stream = php_ssh2_shell_open(session, rsrc, terminal, terminal_len, environment, width, height, type);
    if (!stream) {
        zend_list_delete(rsrc);
    }
    php_url_free(resource);

    return stream;
}
/* }}} */

static php_stream_wrapper_ops php_ssh2_shell_stream_wops = {php_ssh2_fopen_wrapper_shell,
                                                            NULL, /* stream_close */
                                                            NULL, /* stat */
                                                            NULL, /* stat_url */
                                                            NULL, /* opendir */
                                                            "ssh2.shell"};

php_stream_wrapper php_ssh2_stream_wrapper_shell = {&php_ssh2_shell_stream_wops, NULL, 0};

/* {{{ proto stream ssh2_shell(resource session[, string term_type[, array env[, int width, int height[, int
 * width_height_type]]]]) Open a shell at the remote end and allocate a channel for it
 */
PHP_FUNCTION(ssh2_shell) {
    LIBSSH2_SESSION *session;
    php_stream *stream;
    zval *zsession;
    zval *environment = NULL;
    const char *term = PHP_SSH2_DEFAULT_TERMINAL;
    size_t term_len = sizeof(PHP_SSH2_DEFAULT_TERMINAL) - 1;
    zend_long width = PHP_SSH2_DEFAULT_TERM_WIDTH;
    zend_long height = PHP_SSH2_DEFAULT_TERM_HEIGHT;
    zend_long type = PHP_SSH2_DEFAULT_TERM_UNIT;
    int argc = ZEND_NUM_ARGS();

    if (argc == 5) {
        php_error_docref(NULL, E_ERROR, "width specified without height parameter");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(argc, "r|sa!lll", &zsession, &term, &term_len, &environment, &width, &height, &type) ==
        FAILURE) {
        return;
    }

    SSH2_FETCH_AUTHENTICATED_SESSION(session, zsession);

    stream = php_ssh2_shell_open(session, Z_RES_P(zsession), term, term_len, environment, width, height, type);
    if (!stream) {
        RETURN_FALSE;
    }

    /* Ensure that channels are freed BEFORE the sessions they belong to */
    Z_ADDREF_P(zsession);

    php_stream_to_zval(stream, return_value);
}
/* }}} */

PHP_FUNCTION(ssh2_shell_resize) {
    zend_long width;
    zend_long height;
    zend_long width_px = 0;
    zend_long height_px = 0;
    zval *zparent;
    php_stream *parent;
    php_ssh2_channel_data *data;

    int argc = ZEND_NUM_ARGS();

    if (zend_parse_parameters(argc, "rll|ll", &zparent, &width, &height, &width_px, &height_px) == FAILURE) {
        return;
    }

    php_stream_from_zval(parent, zparent);

    if (parent->ops != &php_ssh2_channel_stream_ops) {
        php_error_docref(NULL, E_WARNING, "Provided stream is not of type " PHP_SSH2_CHANNEL_STREAM_NAME);
        RETURN_FALSE;
    }

    data = (php_ssh2_channel_data *) parent->abstract;
    auto session = ssh2_get_session(data);

    libssh2_channel_request_pty_size_ex(data->channel, width, height, width_px, height_px);

    RETURN_TRUE;
}

/* ****************
 * Exec Wrapper *
 **************** */

/* {{{ php_ssh2_exec_command
 * Make a stream from a session
 */
static php_stream *php_ssh2_exec_command(LIBSSH2_SESSION *session,
                                         zend_resource *rsrc,
                                         char *command,
                                         char *term,
                                         int term_len,
                                         zval *environment,
                                         long width,
                                         long height,
                                         long type) {
    LIBSSH2_CHANNEL *channel;
    php_ssh2_channel_data *channel_data;
    php_stream *stream;

    channel = libssh2_channel_open_session(session);
    if (!channel) {
        php_error_docref(NULL, E_WARNING, "Unable to request a channel from remote host");
        return NULL;
    }

    if (environment) {
        zend_string *key = NULL;
        int key_type;
        zend_ulong idx = 0;
        HashPosition pos;

        for (zend_hash_internal_pointer_reset_ex(HASH_OF(environment), &pos);
             (key_type = zend_hash_get_current_key_ex(HASH_OF(environment), &key, &idx, &pos)) != HASH_KEY_NON_EXISTENT;
             zend_hash_move_forward_ex(HASH_OF(environment), &pos)) {
            if (key_type == HASH_KEY_IS_STRING) {
                zval *value;

                if ((value = zend_hash_get_current_data(HASH_OF(environment))) != NULL) {
                    zval copyval = *value;

                    zval_copy_ctor(&copyval);
                    convert_to_string(&copyval);
                    if (libssh2_channel_setenv_ex(channel, key->val, key->len, Z_STRVAL(copyval), Z_STRLEN(copyval))) {
                        php_error_docref(
                            NULL, E_WARNING, "Failed setting %s=%s on remote end", ZSTR_VAL(key), Z_STRVAL(copyval));
                    }
                    zval_dtor(&copyval);
                }
            } else {
                php_error_docref(NULL, E_NOTICE, "Skipping numeric index in environment array");
            }
        }
    }

    if (term) {
        if (type == PHP_SSH2_TERM_UNIT_CHARS) {
            if (libssh2_channel_request_pty_ex(channel, term, term_len, NULL, 0, width, height, 0, 0)) {
                php_error_docref(
                    NULL, E_WARNING, "Failed allocating %s pty at %ldx%ld characters", term, width, height);
                libssh2_channel_free(channel);
                return NULL;
            }
        } else {
            if (libssh2_channel_request_pty_ex(channel, term, term_len, NULL, 0, 0, 0, width, height)) {
                php_error_docref(NULL, E_WARNING, "Failed allocating %s pty at %ldx%ld pixels", term, width, height);
                libssh2_channel_free(channel);
                return NULL;
            }
        }
    }

    if (libssh2_channel_exec(channel, command)) {
        php_error_docref(NULL, E_WARNING, "Unable to request command execution on remote host");
        libssh2_channel_free(channel);
        return NULL;
    }

    /* Turn it into a stream */
    channel_data = (php_ssh2_channel_data *) emalloc(sizeof(php_ssh2_channel_data));
    channel_data->channel = channel;
    channel_data->streamid = 0;
    channel_data->is_blocking = 0;
    channel_data->timeout = 0;
    channel_data->session_rsrc = rsrc;
    channel_data->refcount = NULL;

    stream = php_stream_alloc(&php_ssh2_channel_stream_ops, channel_data, 0, "r+");

    return stream;
}
/* }}} */

/* {{{ php_ssh2_fopen_wrapper_exec
 * ssh2.exec:// fopen wrapper
 */
static php_stream *php_ssh2_fopen_wrapper_exec(php_stream_wrapper *wrapper,
                                               const char *path,
                                               const char *mode,
                                               int options,
                                               zend_string **opened_path,
                                               php_stream_context *context STREAMS_DC) {
    LIBSSH2_SESSION *session = NULL;
    php_stream *stream;
    zval *tmpzval, *environment = NULL;
    zend_resource *rsrc = NULL;
    php_url *resource;
    char *terminal = NULL;
    int terminal_len = 0;
    long width = PHP_SSH2_DEFAULT_TERM_WIDTH;
    long height = PHP_SSH2_DEFAULT_TERM_HEIGHT;
    long type = PHP_SSH2_DEFAULT_TERM_UNIT;

    resource = php_ssh2_fopen_wraper_parse_path(path, "exec", context, &session, &rsrc, NULL, NULL);
    if (!resource || !session) {
        return NULL;
    }
    if (!resource->path) {
        php_url_free(resource);
        zend_list_delete(rsrc);
        return NULL;
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "env")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_ARRAY) {
        environment = tmpzval;
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "term")) != NULL &&
        Z_TYPE_P(tmpzval) == IS_STRING) {
        terminal = Z_STRVAL_P(tmpzval);
        terminal_len = Z_STRLEN_P(tmpzval);
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "term_width")) != NULL) {
        zval copyval;
        copyval = *tmpzval;
        convert_to_long(&copyval);
        width = Z_LVAL_P(&copyval);
        zval_ptr_dtor(&copyval);
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "term_height")) != NULL) {
        zval copyval;
        copyval = *tmpzval;
        convert_to_long(&copyval);
        height = Z_LVAL_P(&copyval);
        zval_ptr_dtor(&copyval);
    }

    if (context && (tmpzval = php_stream_context_get_option(context, "ssh2", "term_units")) != NULL) {
        zval *copyval;
        copyval = tmpzval;
        convert_to_long(copyval);
        type = Z_LVAL_P(copyval);
        zval_ptr_dtor(copyval);
    }

    stream = php_ssh2_exec_command(
        session, rsrc, ZSTR_VAL(resource->path) + 1, terminal, terminal_len, environment, width, height, type);
    if (!stream) {
        zend_list_delete(rsrc);
    }
    php_url_free(resource);

    return stream;
}
/* }}} */

static php_stream_wrapper_ops php_ssh2_exec_stream_wops = {php_ssh2_fopen_wrapper_exec,
                                                           NULL, /* stream_close */
                                                           NULL, /* stat */
                                                           NULL, /* stat_url */
                                                           NULL, /* opendir */
                                                           "ssh2.exec"};

php_stream_wrapper php_ssh2_stream_wrapper_exec = {&php_ssh2_exec_stream_wops, NULL, 0};

/* {{{ proto stream ssh2_exec(resource session, string command[, string pty[, array env[, int width[, int height[, int
 * width_height_type]]]]]) Execute a command at the remote end and allocate a channel for it
 *
 * This function has a dirty little secret.... pty and env can be in either order.... shhhh... don't tell anyone
 */
PHP_FUNCTION(ssh2_exec) {
    LIBSSH2_SESSION *session;
    php_stream *stream;
    zval *zsession;
    zval *environment = NULL;
    zval *zpty = NULL;
    char *command;
    size_t command_len;
    zend_long width = PHP_SSH2_DEFAULT_TERM_WIDTH;
    zend_long height = PHP_SSH2_DEFAULT_TERM_HEIGHT;
    zend_long type = PHP_SSH2_DEFAULT_TERM_UNIT;
    char *term = NULL;
    int term_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(),
                              "rs|z!z!lll",
                              &zsession,
                              &command,
                              &command_len,
                              &zpty,
                              &environment,
                              &width,
                              &height,
                              &type) == FAILURE) {
        return;
    }

    if (zpty && Z_TYPE_P(zpty) == IS_ARRAY) {
        /* Swap pty and environment -- old call style */
        zval *tmp = zpty;
        zpty = environment;
        environment = tmp;
    }

    if (environment && Z_TYPE_P(environment) != IS_ARRAY) {
        php_error_docref(NULL, E_WARNING, "ssh2_exec() expects arg 4 to be of type array");
        RETURN_FALSE;
    }

    if (zpty) {
        convert_to_string(zpty);
        term = Z_STRVAL_P(zpty);
        term_len = Z_STRLEN_P(zpty);
    }

    SSH2_FETCH_AUTHENTICATED_SESSION(session, zsession);

    stream =
        php_ssh2_exec_command(session, Z_RES_P(zsession), command, term, term_len, environment, width, height, type);
    if (!stream) {
        RETURN_FALSE;
    }

    /* Ensure that channels are freed BEFORE the sessions they belong to */
    Z_ADDREF_P(zsession);

    php_stream_to_zval(stream, return_value);
}
/* }}} */

/* ***************
 * SCP Wrapper *
 *************** */

/* {{{ php_ssh2_scp_xfer
 * Make a stream from a session
 */
static php_stream *php_ssh2_scp_xfer(LIBSSH2_SESSION *session, zend_resource *rsrc, char *filename) {
    LIBSSH2_CHANNEL *channel;
    php_ssh2_channel_data *channel_data;
    php_stream *stream;

#ifdef SW_USE_SSH2_ASYNC_HOOK
    php_ssh2_session_data *session_res = libssh2_session_abstract(session);
#endif
    channel = libssh2_scp_recv(session, filename, NULL);
    if (!channel) {
        char *error;
        libssh2_session_last_error(session, &error, NULL, 0);
        php_error_docref(NULL, E_WARNING, "Unable to request a channel from remote host: %s", error);
        return NULL;
    }

    /* Turn it into a stream */
    channel_data = (php_ssh2_channel_data *) emalloc(sizeof(php_ssh2_channel_data));
    channel_data->channel = channel;
    channel_data->streamid = 0;
    channel_data->is_blocking = 0;
    channel_data->timeout = 0;
    channel_data->session_rsrc = rsrc;
    channel_data->refcount = NULL;

    stream = php_stream_alloc(&php_ssh2_channel_stream_ops, channel_data, 0, "r");

    return stream;
}
/* }}} */

/* {{{ php_ssh2_fopen_wrapper_scp
 * ssh2.scp:// fopen wrapper (Read mode only, if you want to know why write mode isn't supported as a stream, take a
 * look at the SCP protocol)
 */
static php_stream *php_ssh2_fopen_wrapper_scp(php_stream_wrapper *wrapper,
                                              const char *path,
                                              const char *mode,
                                              int options,
                                              zend_string **opened_path,
                                              php_stream_context *context STREAMS_DC) {
    LIBSSH2_SESSION *session = NULL;
    php_stream *stream;
    zend_resource *rsrc = NULL;
    php_url *resource;

    if (strchr(mode, '+') || strchr(mode, 'a') || strchr(mode, 'w')) {
        return NULL;
    }

    resource = php_ssh2_fopen_wraper_parse_path(path, "scp", context, &session, &rsrc, NULL, NULL);
    if (!resource || !session) {
        return NULL;
    }
    if (!resource->path) {
        php_url_free(resource);
        zend_list_delete(rsrc);
        return NULL;
    }

    stream = php_ssh2_scp_xfer(session, rsrc, ZSTR_VAL(resource->path));
    if (!stream) {
        zend_list_delete(rsrc);
    }
    php_url_free(resource);

    return stream;
}
/* }}} */

static php_stream_wrapper_ops php_ssh2_scp_stream_wops = {php_ssh2_fopen_wrapper_scp,
                                                          NULL, /* stream_close */
                                                          NULL, /* stat */
                                                          NULL, /* stat_url */
                                                          NULL, /* opendir */
                                                          "ssh2.scp"};

php_stream_wrapper php_ssh2_stream_wrapper_scp = {&php_ssh2_scp_stream_wops, NULL, 0};

/* {{{ proto bool ssh2_scp_recv(resource session, string remote_file, string local_file)
 * Request a file via SCP
 */
PHP_FUNCTION(ssh2_scp_recv) {
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *remote_file;
    struct stat sb;
    php_stream *local_file;
    zval *zsession;
    char *remote_filename, *local_filename;
    size_t remote_filename_len, local_filename_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(),
                              "rss",
                              &zsession,
                              &remote_filename,
                              &remote_filename_len,
                              &local_filename,
                              &local_filename_len) == FAILURE) {
        return;
    }

    SSH2_FETCH_AUTHENTICATED_SESSION(session, zsession);

    remote_file = libssh2_scp_recv(session, remote_filename, &sb);
    if (!remote_file) {
        php_error_docref(NULL, E_WARNING, "Unable to receive remote file");
        RETURN_FALSE;
    }

    local_file = php_stream_open_wrapper(local_filename, "wb", REPORT_ERRORS, NULL);
    if (!local_file) {
        php_error_docref(NULL, E_WARNING, "Unable to write to local file");
        libssh2_channel_free(remote_file);
        RETURN_FALSE;
    }

    while (sb.st_size) {
        char buffer[8192];
        int bytes_read;

        bytes_read = libssh2_channel_read(remote_file, buffer, sb.st_size > 8192 ? 8192 : sb.st_size);
        if (bytes_read < 0) {
            php_error_docref(NULL, E_WARNING, "Error reading from remote file");
            libssh2_channel_free(remote_file);
            php_stream_close(local_file);
            RETURN_FALSE;
        }
        php_stream_write(local_file, buffer, bytes_read);
        sb.st_size -= bytes_read;
    }

    libssh2_channel_free(remote_file);
    php_stream_close(local_file);

    RETURN_TRUE;
}
/* }}} */

/* {{{ proto stream ssh2_scp_send(resource session, string local_file, string remote_file[, int create_mode = 0644])
 * Send a file via SCP
 */
PHP_FUNCTION(ssh2_scp_send) {
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *remote_file;
    php_stream *local_file;
    zval *zsession;
    char *local_filename, *remote_filename;
    size_t local_filename_len, remote_filename_len;
    zend_long create_mode = 0644;
    php_stream_statbuf ssb;
    int argc = ZEND_NUM_ARGS();

    if (zend_parse_parameters(argc,
                              "rss|l",
                              &zsession,
                              &local_filename,
                              &local_filename_len,
                              &remote_filename,
                              &remote_filename_len,
                              &create_mode) == FAILURE) {
        return;
    }

    SSH2_FETCH_AUTHENTICATED_SESSION(session, zsession);

    local_file = php_stream_open_wrapper(local_filename, "rb", REPORT_ERRORS, NULL);
    if (!local_file) {
        php_error_docref(NULL, E_WARNING, "Unable to read source file");
        RETURN_FALSE;
    }

    if (php_stream_stat(local_file, &ssb)) {
        php_error_docref(NULL, E_WARNING, "Failed statting local file");
        php_stream_close(local_file);
        RETURN_FALSE;
    }

    if (argc < 4) {
        create_mode = ssb.sb.st_mode & 0777;
    }

    remote_file =
        libssh2_scp_send_ex(session, remote_filename, create_mode, ssb.sb.st_size, ssb.sb.st_atime, ssb.sb.st_mtime);
    if (!remote_file) {
        int last_error = 0;
        char *error_msg = NULL;

        last_error = libssh2_session_last_error(session, &error_msg, NULL, 0);
        php_error_docref(NULL, E_WARNING, "Failure creating remote file: %s (%d)", error_msg, last_error);
        php_stream_close(local_file);
        RETURN_FALSE;
    }

    while (ssb.sb.st_size) {
        char buffer[8192];
        ssize_t toread = MIN(8192, ssb.sb.st_size);
        ssize_t bytesread = php_stream_read(local_file, buffer, toread);
        ssize_t sent = 0;
        ssize_t justsent = 0;

        if (bytesread <= 0 || bytesread > toread) {
            php_error_docref(NULL, E_WARNING, "Failed copying file 2");
            php_stream_close(local_file);
            libssh2_channel_free(remote_file);
            RETURN_FALSE;
        }

        while (bytesread - sent > 0) {
            if ((justsent = libssh2_channel_write(remote_file, (buffer + sent), bytesread - sent)) < 0) {
                switch (justsent) {
                case LIBSSH2_ERROR_EAGAIN:
                    php_error_docref(NULL, E_WARNING, "Operation would block");
                    break;

                case LIBSSH2_ERROR_ALLOC:
                    php_error_docref(NULL, E_WARNING, "An internal memory allocation call failed");
                    break;

                case LIBSSH2_ERROR_SOCKET_SEND:
                    php_error_docref(NULL, E_WARNING, "Unable to send data on socket");
                    break;

                case LIBSSH2_ERROR_CHANNEL_CLOSED:
                    php_error_docref(NULL, E_WARNING, "The channel has been closed");
                    break;

                case LIBSSH2_ERROR_CHANNEL_EOF_SENT:
                    php_error_docref(NULL, E_WARNING, "The channel has been requested to be closed");
                    break;
                }

                php_stream_close(local_file);
                libssh2_channel_free(remote_file);
                RETURN_FALSE;
            }
            sent = sent + justsent;
        }
        ssb.sb.st_size -= bytesread;
    }

    libssh2_channel_flush_ex(remote_file, LIBSSH2_CHANNEL_FLUSH_ALL);
    php_stream_close(local_file);
    libssh2_channel_free(remote_file);
    RETURN_TRUE;
}
/* }}} */

/* ***************************
 * Direct TCP/IP Transport *
 *************************** */

/* {{{ php_ssh2_direct_tcpip
 * Make a stream from a session
 */
static php_stream *php_ssh2_direct_tcpip(LIBSSH2_SESSION *session, zend_resource *rsrc, char *host, int port) {
    LIBSSH2_CHANNEL *channel;
    php_ssh2_channel_data *channel_data;
    php_stream *stream;

    channel = libssh2_channel_direct_tcpip(session, host, port);
    if (!channel) {
        php_error_docref(NULL, E_WARNING, "Unable to request a channel from remote host");
        return NULL;
    }

    /* Turn it into a stream */
    channel_data = (php_ssh2_channel_data *) emalloc(sizeof(php_ssh2_channel_data));
    channel_data->channel = channel;
    channel_data->streamid = 0;
    channel_data->is_blocking = 0;
    channel_data->timeout = 0;
    channel_data->session_rsrc = rsrc;
    channel_data->refcount = NULL;

    stream = php_stream_alloc(&php_ssh2_channel_stream_ops, channel_data, 0, "r+");

    return stream;
}
/* }}} */

/* {{{ php_ssh2_fopen_wrapper_tunnel
 * ssh2.tunnel:// fopen wrapper
 */
static php_stream *php_ssh2_fopen_wrapper_tunnel(php_stream_wrapper *wrapper,
                                                 const char *path,
                                                 const char *mode,
                                                 int options,
                                                 zend_string **opened_path,
                                                 php_stream_context *context STREAMS_DC) {
    LIBSSH2_SESSION *session = NULL;
    php_stream *stream = NULL;
    php_url *resource;
    char *host = NULL;
    int port = 0;
    zend_resource *rsrc;

    resource = php_ssh2_fopen_wraper_parse_path(path, "tunnel", context, &session, &rsrc, NULL, NULL);
    if (!resource || !session) {
        return NULL;
    }

    if (resource->path && ZSTR_VAL(resource->path)[0] == '/') {
        char *colon;

        host = ZSTR_VAL(resource->path) + 1;
        if (*host == '[') {
            /* IPv6 Encapsulated Format */
            host++;
            colon = strstr(host, "]:");
            if (colon) {
                *colon = 0;
                colon += 2;
            }
        } else {
            colon = strchr(host, ':');
            if (colon) {
                *(colon++) = 0;
            }
        }
        if (colon) {
            port = atoi(colon);
        }
    }

    if ((port <= 0) || (port > 65535) || !host || (strlen(host) == 0)) {
        /* Invalid connection criteria */
        php_url_free(resource);
        zend_list_delete(rsrc);
        return NULL;
    }

    stream = php_ssh2_direct_tcpip(session, rsrc, host, port);
    if (!stream) {
        zend_list_delete(rsrc);
    }
    php_url_free(resource);

    return stream;
}
/* }}} */

static php_stream_wrapper_ops php_ssh2_tunnel_stream_wops = {php_ssh2_fopen_wrapper_tunnel,
                                                             NULL, /* stream_close */
                                                             NULL, /* stat */
                                                             NULL, /* stat_url */
                                                             NULL, /* opendir */
                                                             "ssh2.tunnel"};

php_stream_wrapper php_ssh2_stream_wrapper_tunnel = {&php_ssh2_tunnel_stream_wops, NULL, 0};

/* {{{ proto stream ssh2_tunnel(resource session, string host, int port)
 * Tunnel to remote TCP/IP host/port
 */
PHP_FUNCTION(ssh2_tunnel) {
    LIBSSH2_SESSION *session;
    php_stream *stream;
    zval *zsession;
    char *host;
    size_t host_len;
    zend_long port;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "rsl", &zsession, &host, &host_len, &port) == FAILURE) {
        return;
    }

    SSH2_FETCH_AUTHENTICATED_SESSION(session, zsession);

    stream = php_ssh2_direct_tcpip(session, Z_RES_P(zsession), host, port);
    if (!stream) {
        RETURN_FALSE;
    }

    /* Ensure that channels are freed BEFORE the sessions they belong to */
    Z_ADDREF_P(zsession);

    php_stream_to_zval(stream, return_value);
}
/* }}} */

/* ******************
 * Generic Helper *
 ****************** */

/* {{{ proto stream ssh2_fetch_stream(stream channel, int streamid)
 * Fetch an extended data stream
 */
PHP_FUNCTION(ssh2_fetch_stream) {
    php_ssh2_channel_data *data, *stream_data;
    php_stream *parent, *stream;
    zval *zparent;
    zend_long streamid;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "rl", &zparent, &streamid) == FAILURE) {
        return;
    }

    if (streamid < 0) {
        php_error_docref(NULL, E_WARNING, "Invalid stream ID requested");
        RETURN_FALSE;
    }

    php_stream_from_zval(parent, zparent);

    if (parent->ops != &php_ssh2_channel_stream_ops) {
        php_error_docref(NULL, E_WARNING, "Provided stream is not of type " PHP_SSH2_CHANNEL_STREAM_NAME);
        RETURN_FALSE;
    }

    data = (php_ssh2_channel_data *) parent->abstract;

    if (!data->refcount) {
        data->refcount = (uchar *) emalloc(sizeof(uchar));
        *(data->refcount) = 1;
    }

    if (*(data->refcount) == 255) {
        php_error_docref(NULL, E_WARNING, "Too many streams associated to a single channel");
        RETURN_FALSE;
    }

    (*(data->refcount))++;

    stream_data = (php_ssh2_channel_data *) emalloc(sizeof(php_ssh2_channel_data));
    memcpy(stream_data, data, sizeof(php_ssh2_channel_data));
    stream_data->streamid = streamid;

    stream = php_stream_alloc(&php_ssh2_channel_stream_ops, stream_data, 0, "r+");
    if (!stream) {
        php_error_docref(NULL, E_WARNING, "Error opening substream");
        efree(stream_data);
        (data->refcount)--;
        RETURN_FALSE;
    }

    php_stream_to_zval(stream, return_value);
}
/* }}} */

/* {{{ proto stream ssh2_send_eof(stream channel)
 * Sends EOF to a stream. Primary use is to close stdin of an stdio stream.
 */
PHP_FUNCTION(ssh2_send_eof) {
    php_ssh2_channel_data *data;
    php_stream *parent;
    zval *zparent;
    int ssh2_ret;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &zparent) == FAILURE) {
        return;
    }

    php_stream_from_zval(parent, zparent);
    if (parent->ops != &php_ssh2_channel_stream_ops) {
        php_error_docref(NULL, E_WARNING, "Provided stream is not of type " PHP_SSH2_CHANNEL_STREAM_NAME);
        RETURN_FALSE;
    }

    data = (php_ssh2_channel_data *) parent->abstract;
    if (!data) {
        php_error_docref(NULL, E_WARNING, "Abstract in stream is null");
        RETURN_FALSE;
    }

    auto session = ssh2_get_session(data);

    ssh2_ret = libssh2_channel_send_eof(data->channel);
    if (ssh2_ret < 0) {
        php_error_docref(NULL, E_WARNING, "Couldn't send EOF to channel (Return code %d)", ssh2_ret);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

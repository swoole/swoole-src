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

#ifndef PHP_SSH2_H
#define PHP_SSH2_H

#include "php_swoole_ssh2.h"

#include "ext/standard/url.h"
#include "main/php_network.h"

#define PHP_SSH2_VERSION				"1.4.1"
#define PHP_SSH2_DEFAULT_PORT			22

/* Exported Constants */
#define PHP_SSH2_FINGERPRINT_MD5		0x0000
#define PHP_SSH2_FINGERPRINT_SHA1		0x0001
#define PHP_SSH2_FINGERPRINT_HEX		0x0000
#define PHP_SSH2_FINGERPRINT_RAW		0x0002

#define PHP_SSH2_TERM_UNIT_CHARS		0x0000
#define PHP_SSH2_TERM_UNIT_PIXELS		0x0001

#define PHP_SSH2_DEFAULT_TERMINAL		"vanilla"
#define PHP_SSH2_DEFAULT_TERM_WIDTH		80
#define PHP_SSH2_DEFAULT_TERM_HEIGHT	25
#define PHP_SSH2_DEFAULT_TERM_UNIT		PHP_SSH2_TERM_UNIT_CHARS

#define PHP_SSH2_SESSION_RES_NAME		"SSH2 Session"
#define PHP_SSH2_CHANNEL_STREAM_NAME	"SSH2 Channel"
#define PHP_SSH2_LISTENER_RES_NAME		"SSH2 Listener"
#define PHP_SSH2_SFTP_RES_NAME			"SSH2 SFTP"
#define PHP_SSH2_PKEY_SUBSYS_RES_NAME	"SSH2 Publickey Subsystem"

#define PHP_SSH2_SFTP_STREAM_NAME		"SSH2 SFTP File"
#define PHP_SSH2_SFTP_DIRSTREAM_NAME	"SSH2 SFTP Directory"
#define PHP_SSH2_SFTP_WRAPPER_NAME		"SSH2 SFTP"

#define PHP_SSH2_LISTEN_MAX_QUEUED		16

#define PHP_SSH2_DEFAULT_POLL_TIMEOUT	30

typedef struct _php_ssh2_sftp_data {
	LIBSSH2_SESSION *session;
	LIBSSH2_SFTP *sftp;

	zend_resource *session_rsrc;
} php_ssh2_sftp_data;

typedef struct _php_ssh2_listener_data {
	LIBSSH2_SESSION *session;
	LIBSSH2_LISTENER *listener;

	zend_resource *session_rsrc;
} php_ssh2_listener_data;



typedef struct _php_ssh2_pkey_subsys_data {
	LIBSSH2_SESSION *session;
	LIBSSH2_PUBLICKEY *pkey;

	zend_resource *session_rsrc;
} php_ssh2_pkey_subsys_data;

#define SSH2_FETCH_NONAUTHENTICATED_SESSION(session, zsession) \
if ((session = (LIBSSH2_SESSION *)zend_fetch_resource(Z_RES_P(zsession), PHP_SSH2_SESSION_RES_NAME, le_ssh2_session)) == NULL) { \
	RETURN_FALSE; \
} \
if (libssh2_userauth_authenticated(session)) { \
	php_error_docref(NULL, E_WARNING, "Connection already authenticated"); \
	RETURN_FALSE; \
}

#define SSH2_FETCH_AUTHENTICATED_SESSION(session, zsession) \
if ((session = (LIBSSH2_SESSION *)zend_fetch_resource(Z_RES_P(zsession), PHP_SSH2_SESSION_RES_NAME, le_ssh2_session)) == NULL) { \
	RETURN_FALSE; \
} \
if (!libssh2_userauth_authenticated(session)) { \
	php_error_docref(NULL, E_WARNING, "Connection not authenticated"); \
	RETURN_FALSE; \
}

typedef struct _php_ssh2_channel_data {
	LIBSSH2_CHANNEL *channel;

	/* Distinguish which stream we should read/write from/to */
	unsigned int streamid;
	char is_blocking;
	long timeout;

	/* Resource */
	zend_resource *session_rsrc;

	/* Allow one stream to be closed while the other is kept open */
	unsigned char *refcount;

} php_ssh2_channel_data;

LIBSSH2_SESSION *php_ssh2_session_connect(char *host, int port, zval *methods, zval *callbacks);
void php_ssh2_sftp_dtor(zend_resource *rsrc);
php_url *php_ssh2_fopen_wraper_parse_path(const char *path, char *type, php_stream_context *context,
											LIBSSH2_SESSION **psession, zend_resource **presource,
											LIBSSH2_SFTP **psftp, zend_resource **psftp_rsrc);

extern php_stream_ops php_ssh2_channel_stream_ops;

extern php_stream_wrapper php_ssh2_stream_wrapper_shell;
extern php_stream_wrapper php_ssh2_stream_wrapper_exec;
extern php_stream_wrapper php_ssh2_stream_wrapper_tunnel;
extern php_stream_wrapper php_ssh2_stream_wrapper_scp;
extern php_stream_wrapper php_ssh2_sftp_wrapper;

/* Resource list entries */
extern int le_ssh2_session;
extern int le_ssh2_sftp;

static LIBSSH2_SESSION *ssh2_get_session(php_ssh2_channel_data *abstract) {
	return (LIBSSH2_SESSION *)zend_fetch_resource(abstract->session_rsrc, PHP_SSH2_SESSION_RES_NAME, le_ssh2_session);
}

#endif	/* PHP_SSH2_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * End:
 */

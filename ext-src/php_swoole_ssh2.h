#include "php_swoole_cxx.h"

#include <libssh2.h>
#include <libssh2_sftp.h>
#include <libssh2_publickey.h>

SW_EXTERN_C_BEGIN
#ifdef HAVE_SSH2LIB
ZEND_FUNCTION(ssh2_connect);
ZEND_FUNCTION(ssh2_disconnect);
ZEND_FUNCTION(ssh2_methods_negotiated);
ZEND_FUNCTION(ssh2_fingerprint);
ZEND_FUNCTION(ssh2_auth_none);
ZEND_FUNCTION(ssh2_auth_password);
ZEND_FUNCTION(ssh2_auth_pubkey_file);
ZEND_FUNCTION(ssh2_auth_pubkey);
ZEND_FUNCTION(ssh2_auth_hostbased_file);
ZEND_FUNCTION(ssh2_forward_listen);
ZEND_FUNCTION(ssh2_forward_accept);
ZEND_FUNCTION(ssh2_shell);
ZEND_FUNCTION(ssh2_shell_resize);
ZEND_FUNCTION(ssh2_exec);
ZEND_FUNCTION(ssh2_tunnel);
ZEND_FUNCTION(ssh2_scp_recv);
ZEND_FUNCTION(ssh2_scp_send);
ZEND_FUNCTION(ssh2_fetch_stream);
ZEND_FUNCTION(ssh2_poll);
ZEND_FUNCTION(ssh2_send_eof);
ZEND_FUNCTION(ssh2_sftp);
ZEND_FUNCTION(ssh2_sftp_rename);
ZEND_FUNCTION(ssh2_sftp_unlink);
ZEND_FUNCTION(ssh2_sftp_mkdir);
ZEND_FUNCTION(ssh2_sftp_rmdir);
ZEND_FUNCTION(ssh2_sftp_chmod);
ZEND_FUNCTION(ssh2_sftp_stat);
ZEND_FUNCTION(ssh2_sftp_lstat);
ZEND_FUNCTION(ssh2_sftp_symlink);
ZEND_FUNCTION(ssh2_sftp_readlink);
ZEND_FUNCTION(ssh2_sftp_realpath);
ZEND_FUNCTION(ssh2_publickey_init);
ZEND_FUNCTION(ssh2_publickey_add);
ZEND_FUNCTION(ssh2_publickey_remove);
ZEND_FUNCTION(ssh2_publickey_list);
ZEND_FUNCTION(ssh2_auth_agent);
#endif
SW_EXTERN_C_END

typedef std::function<int(swoole::coroutine::Socket *, LIBSSH2_SESSION *session)> Ssh2Fn;

typedef struct _php_ssh2_session_data {
	/* Userspace callback functions */
	zval *ignore_cb;
	zval *debug_cb;
	zval *macerror_cb;
	zval *disconnect_cb;

	swoole::coroutine::Socket *socket;
} php_ssh2_session_data;

static int ssh2_async_call(swoole::coroutine::Socket *socket, LIBSSH2_SESSION *session, const Ssh2Fn &fn) {
	int dir = libssh2_session_block_directions(session);
	swoole::EventType event;
    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
    	event = SW_EVENT_WRITE;
    } else {
    	event = SW_EVENT_READ;
    }

	int rc;
	while (1) {
		rc = fn(socket, session);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			if (!socket->poll(event)) {
				return -1;
			}
			continue;
		}
		if (rc) {
			return rc;
		}
		break;
	}
	return 0;
}

static swoole::coroutine::Socket *ssh2_get_socket(LIBSSH2_SESSION *session) {
	auto session_data = (php_ssh2_session_data **) libssh2_session_abstract(session);
	return (*session_data)->socket;
}

static int ssh2_async_call(LIBSSH2_SESSION *session, const Ssh2Fn &fn) {
	return ssh2_async_call(ssh2_get_socket(session), session, fn);
}


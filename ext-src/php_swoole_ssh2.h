/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2023 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
*/
#ifndef SWOOLE_SRC_PHP_SWOOLE_SSH2_H
#define SWOOLE_SRC_PHP_SWOOLE_SSH2_H

#include "php_swoole.h"

#ifdef SW_USE_SSH2

BEGIN_EXTERN_C()

#include <libssh2.h>
#include <libssh2_sftp.h>

#define SW_SSH2_FETCH_SESSION(session, zsession) \
if ((session = (LIBSSH2_SESSION *)zend_fetch_resource(Z_RES_P(zsession), PHP_SSH2_SESSION_RES_NAME, le_ssh2_session)) == NULL) { \
	RETURN_FALSE; \
}

#define SW_SSH2_FETCH_AUTHENTICATED_SESSION(session, zsession) \
SW_SSH2_FETCH_SESSION(session, zsession) \
if (!libssh2_userauth_authenticated(session)) { \
	php_error_docref(NULL, E_WARNING, "Connection not authenticated"); \
	RETURN_FALSE; \
}

extern void swoole_ssh2_set_blocking(bool blocking);
extern LIBSSH2_SESSION *swoole_libssh2_session_init_ex(LIBSSH2_MEMORY_CALLBACK mem_alloc, LIBSSH2_MEMORY_CALLBACK mem_free, LIBSSH2_MEMORY_CALLBACK mem_realloc, void *abstract);
extern int swoole_libssh2_session_startup(LIBSSH2_SESSION *session, int socket);
extern int swoole_libssh2_session_handshake(LIBSSH2_SESSION *session, int socket);
extern int swoole_libssh2_userauth_password(LIBSSH2_SESSION *session, const char *username, const char *password);
extern int swoole_libssh2_userauth_publickey_fromfile(LIBSSH2_SESSION *session, const char *username, const char *publickey, const char *privatekey, const char *passphrase);
extern int swoole_libssh2_userauth_publickey(LIBSSH2_SESSION *session, const char *username, int username_len, const char *publickey, int publickey_len, const char *privatekey, int privatekey_len, const char *passphrase);
extern int swoole_libssh2_userauth_hostbased_fromfile(LIBSSH2_SESSION *session, const char *username, const char *hostname, const char *publickey, const char *privatekey, const char *passphrase, const char *local_username);
extern int swoole_libssh2_userauth_hostbased(LIBSSH2_SESSION *session, const char *username, int username_len, const char *hostname, int hostname_len, const char *publickey, int publickey_len, const char *privatekey, int privatekey_len, const char *passphrase, const char *local_username, int local_username_len);
extern int swoole_libssh2_userauth_none(LIBSSH2_SESSION *session, const char *username);
extern int swoole_libssh2_userauth_agent(LIBSSH2_SESSION *session, const char *username);
extern int swoole_libssh2_session_disconnect_ex(LIBSSH2_SESSION *session, int reason, const char *desc, const char *lang);
extern void swoole_libssh2_session_free(LIBSSH2_SESSION *session);
extern int swoole_libssh2_session_last_error(LIBSSH2_SESSION *session, char **string, int *string_len, int want_clear);
extern int swoole_libssh2_session_banner_set(LIBSSH2_SESSION *session, const char *banner);
extern const char *swoole_libssh2_session_banner_get(LIBSSH2_SESSION *session);
extern int swoole_libssh2_session_method_pref(LIBSSH2_SESSION *session, int method_type, const char *method_list);
extern int swoole_libssh2_session_get_blocking(LIBSSH2_SESSION *session);
extern int swoole_libssh2_session_set_blocking(LIBSSH2_SESSION *session, int blocking);
extern int swoole_libssh2_session_set_timeout(LIBSSH2_SESSION *session, long timeout);
extern long swoole_libssh2_session_last_errno(LIBSSH2_SESSION *session);
extern int swoole_libssh2_session_set_compress(LIBSSH2_SESSION *session, int onoff);
extern int swoole_libssh2_hostkey_hash(LIBSSH2_SESSION *session, int hash_type);
extern const char *swoole_libssh2_version(int required_version);

extern LIBSSH2_CHANNEL *swoole_libssh2_channel_open_ex(LIBSSH2_SESSION *session, const char *channel_type, unsigned int channel_type_len, unsigned int window_size, unsigned int packet_size, const char *message, unsigned int message_len);
extern int swoole_libssh2_channel_exec(LIBSSH2_CHANNEL *channel, const char *command);
extern int swoole_libssh2_channel_shell_ex(LIBSSH2_CHANNEL *channel, const char *term, const char **env, int env_count, int width, int height, int width_px, int height_px);
extern int swoole_libssh2_channel_read(LIBSSH2_CHANNEL *channel, char *buf, unsigned int buflen);
extern int swoole_libssh2_channel_read_ex(LIBSSH2_CHANNEL *channel, int stream_id, char *buf, unsigned int buflen);
extern int swoole_libssh2_channel_write(LIBSSH2_CHANNEL *channel, const char *buf, unsigned int buflen);
extern int swoole_libssh2_channel_write_ex(LIBSSH2_CHANNEL *channel, int stream_id, const char *buf, unsigned int buflen);
extern int swoole_libssh2_channel_send_eof(LIBSSH2_CHANNEL *channel);
extern int swoole_libssh2_channel_close(LIBSSH2_CHANNEL *channel);
extern int swoole_libssh2_channel_wait_closed(LIBSSH2_CHANNEL *channel);
extern int swoole_libssh2_channel_wait_eof(LIBSSH2_CHANNEL *channel);
extern int swoole_libssh2_channel_window_read(LIBSSH2_CHANNEL *channel, unsigned int *window_size_initial, unsigned int *window_size_actual);
extern int swoole_libssh2_channel_window_write(LIBSSH2_CHANNEL *channel, unsigned int *window_size_initial, unsigned int *window_size_actual);
extern int swoole_libssh2_channel_get_exit_status(LIBSSH2_CHANNEL *channel);
extern int swoole_libssh2_channel_get_exit_signal(LIBSSH2_CHANNEL *channel, char **sig_name, char **sig_specific, char **lang_tag, int *exit_code);
extern int swoole_libssh2_channel_request_pty_ex(LIBSSH2_CHANNEL *channel, const char *term, unsigned int term_len, int width, int height, int width_px, int height_px, const char *terminal_mode, unsigned int terminal_mode_len);
extern int swoole_libssh2_channel_request_pty_size_ex(LIBSSH2_CHANNEL *channel, int width, int height, int width_px, int height_px);
extern int swoole_libssh2_channel_subsystem(LIBSSH2_CHANNEL *channel, const char *subsystem);
extern int swoole_libssh2_channel_x11_req_ex(LIBSSH2_CHANNEL *channel, int single_connection, const char *auth_protocol, const char *auth_cookie, int screen_number);

extern LIBSSH2_LISTENER *swoole_libssh2_channel_forward_listen_ex(LIBSSH2_SESSION *session, const char *bindaddr, int port, int queue_maxsize);
extern LIBSSH2_CHANNEL *swoole_libssh2_channel_forward_accept(LIBSSH2_LISTENER *listener);
extern int swoole_libssh2_channel_forward_cancel(LIBSSH2_LISTENER *listener);

extern LIBSSH2_CHANNEL *swoole_libssh2_channel_direct_tcpip_ex(LIBSSH2_SESSION *session, const char *host, int port, const char *shost, int sport);

extern int swoole_libssh2_scp_send(LIBSSH2_SESSION *session, const char *sourcefile, const char *remotepath, int mode, size_t size);
extern int swoole_libssh2_scp_recv(LIBSSH2_SESSION *session, const char *remotepath, char *localpath);

extern LIBSSH2_SFTP *swoole_libssh2_sftp_init(LIBSSH2_SESSION *session);
extern int swoole_libssh2_sftp_shutdown(LIBSSH2_SFTP *sftp_session);
extern LIBSSH2_SFTP_HANDLE *swoole_libssh2_sftp_open(LIBSSH2_SFTP *sftp_session, const char *path, unsigned int flags, long mode);
extern int swoole_libssh2_sftp_close(LIBSSH2_SFTP_HANDLE *handle);
extern int swoole_libssh2_sftp_read(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen);
extern int swoole_libssh2_sftp_write(LIBSSH2_SFTP_HANDLE *handle, const char *buffer, size_t count);
extern int64_t swoole_libssh2_sftp_tell(LIBSSH2_SFTP_HANDLE *handle);
extern int swoole_libssh2_sftp_seek(LIBSSH2_SFTP_HANDLE *handle, int64_t offset);
extern int swoole_libssh2_sftp_stat(LIBSSH2_SFTP *sftp_session, const char *path, LIBSSH2_SFTP_ATTRIBUTES *attrs);
extern int swoole_libssh2_sftp_lstat(LIBSSH2_SFTP *sftp_session, const char *path, LIBSSH2_SFTP_ATTRIBUTES *attrs);
extern int swoole_libssh2_sftp_fstat(LIBSSH2_SFTP_HANDLE *handle, LIBSSH2_SFTP_ATTRIBUTES *attrs);
extern int swoole_libssh2_sftp_symlink(LIBSSH2_SFTP *sftp_session, const char *targetpath, const char *linkpath);
extern int swoole_libssh2_sftp_readlink(LIBSSH2_SFTP *sftp_session, const char *path, char *targetpath, size_t maxlen);
extern int swoole_libssh2_sftp_rename(LIBSSH2_SFTP *sftp_session, const char *sourcepath, const char *targetpath);
extern int swoole_libssh2_sftp_unlink(LIBSSH2_SFTP *sftp_session, const char *path);
extern int swoole_libssh2_sftp_mkdir(LIBSSH2_SFTP *sftp_session, const char *path, long mode);
extern int swoole_libssh2_sftp_rmdir(LIBSSH2_SFTP *sftp_session, const char *path);
extern int swoole_libssh2_sftp_chmod(LIBSSH2_SFTP *sftp_session, const char *path, long mode);
extern int swoole_libssh2_sftp_chown(LIBSSH2_SFTP *sftp_session, const char *path, long owner, long group);
extern int swoole_libssh2_sftp_fchown(LIBSSH2_SFTP_HANDLE *handle, long owner, long group);
extern int swoole_libssh2_sftp_chmod(LIBSSH2_SFTP *sftp_session, const char *path, long mode);
extern int swoole_libssh2_sftp_fchmod(LIBSSH2_SFTP_HANDLE *handle, long mode);
extern LIBSSH2_SFTP_DIR *swoole_libssh2_sftp_opendir(LIBSSH2_SFTP *sftp_session, const char *path);
extern int swoole_libssh2_sftp_closedir(LIBSSH2_SFTP_DIR *dir);
extern LIBSSH2_SFTP_ATTRIBUTES *swoole_libssh2_sftp_readdir(LIBSSH2_SFTP_DIR *dir, char *filename, unsigned int filename_maxlen, LIBSSH2_SFTP_ATTRIBUTES *attrs);

extern LIBSSH2_PUBLICKEY *swoole_libssh2_publickey_init(LIBSSH2_SESSION *session);
extern int swoole_libssh2_publickey_list(LIBSSH2_PUBLICKEY *pkey, int *num_keys, LIBSSH2_PUBLICKEY_LIST **key_list);
extern int swoole_libssh2_publickey_add_ex(LIBSSH2_PUBLICKEY *pkey, const char *name, int name_len, const unsigned char *blob, unsigned int blob_len, const char *comment, unsigned int comment_len, unsigned int overwrite);
extern int swoole_libssh2_publickey_remove(LIBSSH2_PUBLICKEY *pkey, const char *name, int name_len, const unsigned char *blob, unsigned int blob_len);
extern void swoole_libssh2_publickey_free(LIBSSH2_PUBLICKEY *pkey);

extern int swoole_libssh2_poll(LIBSSH2_SESSION *session, struct libssh2_pollfd **fds, unsigned int nfds, int timeout_ms);

extern void swoole_ssh2_minit(int module_id);
extern void swoole_ssh2_mshutdown();

/* Hook macros */
#ifdef SW_USE_SSH2_HOOK
#define libssh2_session_init_ex swoole_libssh2_session_init_ex
#define libssh2_session_startup swoole_libssh2_session_startup
#define libssh2_session_handshake swoole_libssh2_session_handshake
#define libssh2_userauth_password swoole_libssh2_userauth_password
#define libssh2_userauth_publickey_fromfile swoole_libssh2_userauth_publickey_fromfile
#define libssh2_userauth_publickey swoole_libssh2_userauth_publickey
#define libssh2_userauth_hostbased_fromfile swoole_libssh2_userauth_hostbased_fromfile
#define libssh2_userauth_hostbased swoole_libssh2_userauth_hostbased
#define libssh2_userauth_none swoole_libssh2_userauth_none
#define libssh2_userauth_agent swoole_libssh2_userauth_agent
#define libssh2_session_disconnect_ex swoole_libssh2_session_disconnect_ex
#define libssh2_session_free swoole_libssh2_session_free
#define libssh2_session_last_error swoole_libssh2_session_last_error
#define libssh2_session_banner_set swoole_libssh2_session_banner_set
#define libssh2_session_banner_get swoole_libssh2_session_banner_get
#define libssh2_session_method_pref swoole_libssh2_session_method_pref
#define libssh2_session_get_blocking swoole_libssh2_session_get_blocking
#define libssh2_session_set_blocking swoole_libssh2_session_set_blocking
#define libssh2_session_set_timeout swoole_libssh2_session_set_timeout
#define libssh2_session_last_errno swoole_libssh2_session_last_errno
#define libssh2_session_set_compress swoole_libssh2_session_set_compress
#define libssh2_hostkey_hash swoole_libssh2_hostkey_hash
#define libssh2_version swoole_libssh2_version

#define libssh2_channel_open_ex swoole_libssh2_channel_open_ex
#define libssh2_channel_exec swoole_libssh2_channel_exec
#define libssh2_channel_shell_ex swoole_libssh2_channel_shell_ex
#define libssh2_channel_read swoole_libssh2_channel_read
#define libssh2_channel_read_ex swoole_libssh2_channel_read_ex
#define libssh2_channel_write swoole_libssh2_channel_write
#define libssh2_channel_write_ex swoole_libssh2_channel_write_ex
#define libssh2_channel_send_eof swoole_libssh2_channel_send_eof
#define libssh2_channel_close swoole_libssh2_channel_close
#define libssh2_channel_wait_closed swoole_libssh2_channel_wait_closed
#define libssh2_channel_wait_eof swoole_libssh2_channel_wait_eof
#define libssh2_channel_window_read swoole_libssh2_channel_window_read
#define libssh2_channel_window_write swoole_libssh2_channel_window_write
#define libssh2_channel_get_exit_status swoole_libssh2_channel_get_exit_status
#define libssh2_channel_get_exit_signal swoole_libssh2_channel_get_exit_signal
#define libssh2_channel_request_pty_ex swoole_libssh2_channel_request_pty_ex
#define libssh2_channel_request_pty_size_ex swoole_libssh2_channel_request_pty_size_ex
#define libssh2_channel_subsystem swoole_libssh2_channel_subsystem
#define libssh2_channel_x11_req_ex swoole_libssh2_channel_x11_req_ex

#define libssh2_channel_forward_listen_ex swoole_libssh2_channel_forward_listen_ex
#define libssh2_channel_forward_accept swoole_libssh2_channel_forward_accept
#define libssh2_channel_forward_cancel swoole_libssh2_channel_forward_cancel

#define libssh2_channel_direct_tcpip_ex swoole_libssh2_channel_direct_tcpip_ex

#define libssh2_scp_send swoole_libssh2_scp_send
#define libssh2_scp_recv swoole_libssh2_scp_recv

#define libssh2_sftp_init swoole_libssh2_sftp_init
#define libssh2_sftp_shutdown swoole_libssh2_sftp_shutdown
#define libssh2_sftp_open swoole_libssh2_sftp_open
#define libssh2_sftp_close swoole_libssh2_sftp_close
#define libssh2_sftp_read swoole_libssh2_sftp_read
#define libssh2_sftp_write swoole_libssh2_sftp_write
#define libssh2_sftp_tell swoole_libssh2_sftp_tell
#define libssh2_sftp_seek swoole_libssh2_sftp_seek
#define libssh2_sftp_stat swoole_libssh2_sftp_stat
#define libssh2_sftp_lstat swoole_libssh2_sftp_lstat
#define libssh2_sftp_fstat swoole_libssh2_sftp_fstat
#define libssh2_sftp_symlink swoole_libssh2_sftp_symlink
#define libssh2_sftp_readlink swoole_libssh2_sftp_readlink
#define libssh2_sftp_rename swoole_libssh2_sftp_rename
#define libssh2_sftp_unlink swoole_libssh2_sftp_unlink
#define libssh2_sftp_mkdir swoole_libssh2_sftp_mkdir
#define libssh2_sftp_rmdir swoole_libssh2_sftp_rmdir
#define libssh2_sftp_chmod swoole_libssh2_sftp_chmod
#define libssh2_sftp_chown swoole_libssh2_sftp_chown
#define libssh2_sftp_fchown swoole_libssh2_sftp_fchown
#define libssh2_sftp_fchmod swoole_libssh2_sftp_fchmod
#define libssh2_sftp_opendir swoole_libssh2_sftp_opendir
#define libssh2_sftp_closedir swoole_libssh2_sftp_closedir
#define libssh2_sftp_readdir swoole_libssh2_sftp_readdir

#define libssh2_publickey_init swoole_libssh2_publickey_init
#define libssh2_publickey_list swoole_libssh2_publickey_list
#define libssh2_publickey_add_ex swoole_libssh2_publickey_add_ex
#define libssh2_publickey_remove swoole_libssh2_publickey_remove
#define libssh2_publickey_free swoole_libssh2_publickey_free

#define libssh2_poll swoole_libssh2_poll
#endif

END_EXTERN_C()
#endif
#endif
#include "php.h"

BEGIN_EXTERN_C()
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
END_EXTERN_C()

int php_swoole_ssh2_mshutdown();
int php_swoole_ssh2_minit(int module_number);
void php_swoole_ssh2_minfo();

#ifndef EXT_SRC_PHP_SWOOLE_FTP_DEF_H_
#define EXT_SRC_PHP_SWOOLE_FTP_DEF_H_

#include "php.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

BEGIN_EXTERN_C()
ZEND_FUNCTION(ftp_connect);
#if defined(SW_HAVE_FTP_SSL)
ZEND_FUNCTION(ftp_ssl_connect);
#endif
ZEND_FUNCTION(ftp_login);
ZEND_FUNCTION(ftp_pwd);
ZEND_FUNCTION(ftp_cdup);
ZEND_FUNCTION(ftp_chdir);
ZEND_FUNCTION(ftp_exec);
ZEND_FUNCTION(ftp_raw);
ZEND_FUNCTION(ftp_mkdir);
ZEND_FUNCTION(ftp_rmdir);
ZEND_FUNCTION(ftp_chmod);
ZEND_FUNCTION(ftp_alloc);
ZEND_FUNCTION(ftp_nlist);
ZEND_FUNCTION(ftp_rawlist);
ZEND_FUNCTION(ftp_mlsd);
ZEND_FUNCTION(ftp_systype);
ZEND_FUNCTION(ftp_fget);
ZEND_FUNCTION(ftp_nb_fget);
ZEND_FUNCTION(ftp_pasv);
ZEND_FUNCTION(ftp_get);
ZEND_FUNCTION(ftp_nb_get);
ZEND_FUNCTION(ftp_nb_continue);
ZEND_FUNCTION(ftp_fput);
ZEND_FUNCTION(ftp_nb_fput);
ZEND_FUNCTION(ftp_put);
ZEND_FUNCTION(ftp_append);
ZEND_FUNCTION(ftp_nb_put);
ZEND_FUNCTION(ftp_size);
ZEND_FUNCTION(ftp_mdtm);
ZEND_FUNCTION(ftp_rename);
ZEND_FUNCTION(ftp_delete);
ZEND_FUNCTION(ftp_site);
ZEND_FUNCTION(ftp_close);
ZEND_FUNCTION(ftp_set_option);
ZEND_FUNCTION(ftp_get_option);

PHP_MINIT_FUNCTION(ftp);
PHP_MINFO_FUNCTION(ftp);
END_EXTERN_C()

#endif

/*
  +----------------------------------------------------------------------+
  | Copyright (c) The PHP Group                                          |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | https://www.php.net/license/3_01.txt                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:  Zeev Suraski <zeev@php.net>                                 |
  +----------------------------------------------------------------------+
*/

#include "main/php_variables.h"

/**
 * This only handles the cases of PARSE_STRING and PARSE_COOKIE
 */
static void swoole_php_treat_data(int arg, char *str, zval *destArray) {
    char *res = NULL, *var, *val, *separator = NULL;
    zval array;
    int free_buffer = 0;
    char *strtok_buf = NULL;
    zend_long count = 0;

    ZVAL_UNDEF(&array);
    ZVAL_COPY_VALUE(&array, destArray);

    res = str;
    free_buffer = 1;

    if (!res) {
        return;
    }

    switch (arg) {
    case PARSE_STRING:
        separator = PG(arg_separator).input;
        break;
    case PARSE_COOKIE:
        separator = (char *) ";\0";
        break;
    }

    var = php_strtok_r(res, separator, &strtok_buf);

    while (var) {
        size_t val_len;
        size_t new_val_len;

        val = strchr(var, '=');

        if (arg == PARSE_COOKIE) {
            /* Remove leading spaces from cookie names, needed for multi-cookie header where ; can be followed by a
             * space */
            while (isspace(*var)) {
                var++;
            }
            if (var == val || *var == '\0') {
                goto next_cookie;
            }
        }

        if (++count > PG(max_input_vars)) {
            swoole_warning("Input variables exceeded " ZEND_LONG_FMT
                           ". To increase the limit change max_input_vars in php.ini.",
                           PG(max_input_vars));
            break;
        }

        if (val) { /* have a value */
            *val++ = '\0';
            if (arg == PARSE_COOKIE) {
                val_len = php_raw_url_decode(val, strlen(val));
            } else {
                val_len = php_url_decode(val, strlen(val));
            }
        } else {
            val = (char *) "";
            val_len = 0;
        }

        val = estrndup(val, val_len);
        if (arg != PARSE_COOKIE) {
            php_url_decode(var, strlen(var));
        }

        if (sapi_module.input_filter(PARSE_STRING, var, &val, val_len, &new_val_len)) {
            if (arg == PARSE_STRING ||
                (arg == PARSE_COOKIE && !zend_symtable_str_exists(Z_ARRVAL_P(&array), var, strlen(var)))) {
                php_register_variable_safe(var, val, new_val_len, &array);
            }
        }
        efree(val);
    next_cookie:
        var = php_strtok_r(NULL, separator, &strtok_buf);
    }

    if (free_buffer) {
        efree(res);
    }
}

#include "php_swoole_cxx.h"

typedef int php_file_descriptor_t;
typedef pid_t php_process_id_t;

extern "C"
{
PHP_FUNCTION(swoole_proc_open);
PHP_FUNCTION(swoole_proc_close);
PHP_FUNCTION(swoole_proc_get_status);
PHP_FUNCTION(swoole_proc_terminate);
}

void swoole_proc_open_init(int module_number);

struct php_co_process_env_t
{
    char *envp;
    char **envarray;
};

struct php_co_process_t
{
    php_process_id_t child;
    bool exited;
    int npipes;
    int *wstatus;
    zend_resource **pipes;
    char *command;
    php_co_process_env_t env;
};

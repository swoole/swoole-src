#include "php_swoole_cxx.h"

extern "C"
{
PHP_FUNCTION(swoole_proc_open);
PHP_FUNCTION(swoole_proc_close);
PHP_FUNCTION(swoole_proc_get_status);
PHP_FUNCTION(swoole_proc_terminate);
}

void swoole_proc_open_init(int module_number);

struct proc_co_env_t
{
    char *envp;
    char **envarray;
};

struct proc_co_t
{
    pid_t child;
    bool running;
    int npipes;
    int *wstatus;
    zend_resource **pipes;
    char *command;
    proc_co_env_t env;
};

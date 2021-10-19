BEGIN_EXTERN_C()
#if PHP_VERSION_ID < 80000
#include "php_swoole_legacy_arginfo.h"
#else
#include "php_swoole_arginfo.h"
#endif
END_EXTERN_C()

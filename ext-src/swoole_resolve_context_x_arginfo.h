BEGIN_EXTERN_C()
#if PHP_VERSION_ID < 80000
#include "swoole_resolve_context_legacy_arginfo.h"
#else
#include "swoole_resolve_context_arginfo.h"
#endif
END_EXTERN_C()

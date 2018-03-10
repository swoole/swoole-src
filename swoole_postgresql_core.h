#include <libpq-fe.h>

typedef struct _php_pgsql_result_handle {
    PGconn *conn;
    PGresult *result;
    int row;
} pgsql_result_handle;

#define PGSQL_ASSOC           1<<0
#define PGSQL_NUM             1<<1
#define PGSQL_BOTH            (PGSQL_ASSOC|PGSQL_NUM)

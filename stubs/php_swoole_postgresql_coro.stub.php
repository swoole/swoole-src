<?php
namespace Swoole\Coroutine {
    class PostgreSQL {
        public function __construct() {}
        public function __destruct() {}
        public function connect(string $conninfo, float $timeout = 2): bool {}
        public function escape(string $string): false|string {}
        public function escapeLiteral(string $string): false|string {}
        public function escapeIdentifier(string $string): false|string {}
        public function query(string $query): false|PostgreSQLStatement {}
        public function prepare(string $query): false|PostgreSQLStatement {}
        public function metaData(string $table_name): false|array {}
    }

    class PostgreSQLStatement {
        public function execute(array $params = []): bool {}
        public function fetchAll(int $result_type = SW_PGSQL_ASSOC): false|array {}
        public function affectedRows(): int {}
        public function numRows(): int {}
        public function fieldCount(): int {}
        public function fetchObject(?int $row = 0, ?string $class_name = null, array $ctor_params = []): false|object {}
        public function fetchAssoc(?int $row = 0, int $result_type = SW_PGSQL_ASSOC): false|array {}
        public function fetchArray(?int $row = 0, int $result_type = SW_PGSQL_BOTH): false|array {}
        public function fetchRow(?int $row = 0, int $result_type = SW_PGSQL_NUM): false|array {}
    }
}

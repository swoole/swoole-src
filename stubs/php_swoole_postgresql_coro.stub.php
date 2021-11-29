<?php
namespace Swoole\Coroutine {
    class PostgreSQL {
        public function __construct() {}
        public function __destruct() {}
        public function connect(string $conninfo, float $timeout = 2): bool {}
        public function escape(string $string): false|string {}
        public function escapeLiteral(string $string): false|string {}
        public function escapeIdentifier(string $string): false|string {}
        /**
         * @return resource|false
         */
        public function query(string $query) {}
        public function prepare(string $stmtname, string $query): ?bool {}
        public function execute(string $stmtname, array $pv_param_arr): ?bool {}
        /**
         * @param resource $result
         */
        public function fetchAll($result, int $result_type = SW_PGSQL_ASSOC): false|array {}
         /**
          * @param resource $result
          */
        public function affectedRows($result): int {}
        /**
         * @param resource $result
         */
        public function numRows($result): int {}
         /**
          * @param resource $result
          */
        public function fieldCount($result): int {}
        public function metaData(string $table_name): false|array {}
        /**
         * @param resource $result
         */
        public function fetchObject($result, ?int $row = 0, ?string $class_name = null, array $ctor_params = []): false|object {}
        /**
         * @param resource $result
         */
        public function fetchAssoc($result, ?int $row = 0, int $result_type = SW_PGSQL_ASSOC): false|array {}
        /**
         * @param resource $result
         */
        public function fetchArray($result, ?int $row = 0, int $result_type = SW_PGSQL_BOTH): false|array {}
        /**
         * @param resource $result
         */
        public function fetchRow($result, ?int $row = 0, int $result_type = SW_PGSQL_NUM): false|array {}
    }
}

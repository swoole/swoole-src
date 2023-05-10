<?php
declare(strict_types=1);

class pdo_pgsql_test_inc
{
    const TABLE = 'test_swoole_pgsql_user';

    public static function init(): void
    {
        $pdo = self::create();
        if (!self::tableExists($pdo, self::TABLE)) {
            $pdo->exec('CREATE TABLE ' . self::TABLE . ' (
                id SERIAL primary key NOT NULL,
                name character varying(32),
                age integer)');
        }

        $pdo->exec('TRUNCATE ' . self::TABLE);
    }

    public static function getTable()
    {
        return self::TABLE;
    }

    public static function tableExists($pdo, $table)
    {
        try {
            $result = $pdo->query("SELECT 1 FROM {$table} LIMIT 1");
        } catch (Exception $e) {
            return false;
        }

        return $result !== false;
    }

    public static function create(): PDO
    {
        $host = PGSQL_HOST;
        $port = PGSQL_PORT;
        $user = PGSQL_USER;
        $password = PGSQL_PASSWORD;
        $dbname = PGSQL_DBNAME;
        return new PDO("pgsql:host={$host};port={$port};dbname={$dbname}", $user, $password);
    }
}

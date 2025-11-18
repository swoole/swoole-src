<?php
declare(strict_types=1);

class PdoFirebirdTest
{
    public static function skip() {
        try {
            $db = self::create();
        } catch (PDOException $e) {
            die("skip " . $e->getMessage());
        }
    }

    public static function create(): PDO
    {
        return new PDO(FIREBIRD_DSN, FIREBIRD_USER, FIREBIRD_PASSWORD);
    }
}

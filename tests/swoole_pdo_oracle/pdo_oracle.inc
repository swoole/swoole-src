<?php
declare(strict_types=1);

class PdoOracleTest
{
    public static function tableName(string $prefix): string
    {
        // Keep names below Oracle's 30-byte identifier limit and isolate PHPT
        // workers/retries, including after a previous process crashed.
        return $prefix . '_' . bin2hex(random_bytes(6));
    }

     public static function skip() {
        try {
            $db = self::create();
        } catch (PDOException $e) {
            die("skip " . $e->getMessage());
        }
     }

    public static function create(): PDO
    {
        $db = new PDO(ORACLE_TNS, ORACLE_USER, ORACLE_PASSWORD);
        $db->setAttribute(PDO::ATTR_CASE, PDO::CASE_LOWER);
        return $db;
    }
}

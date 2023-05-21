<?php
declare(strict_types=1);

class PdoOracleTest
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
        $db = new PDO(ORACLE_TNS, ORACLE_USER, ORACLE_PASSWORD);
        $db->setAttribute(PDO::ATTR_CASE, PDO::CASE_LOWER);
        return $db;
    }
}

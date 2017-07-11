<?php
require_once __DIR__ . "/swoole_mysql_init.php";
define("MAX_UNSIGNED_BIGINT", "18446744073709551615");


class Mysql
{
//    public $swoole_mysql;
    public $sql;
    public $r;
    public function __construct()
    {
//        $this->swoole_mysql = new \mysqli();
//        $r = $this->swoole_mysql->real_connect("127.0.0.1", "root", "", "test", 3306);
//        assert($r === true);
//
        $id = MAX_UNSIGNED_BIGINT;
        $varbin = fread(fopen("/dev/urandom", "r"), 1024);


        $sql = $r = [];
        $sql[] = "DROP TABLE IF EXISTS `type_test`";
        $r[] = true;
        $sql[] = "CREATE TABLE `type_test` (
  `id` bigint(20) unsigned DEFAULT NULL,
  `varbin` varbinary(1024) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        $r[] = true;
        $sql[] = "SET sql_mode = 'NO_UNSIGNED_SUBTRACTION';";
        $r[] = true;
        $sql[] = "insert into `type_test` (`id`, `varbin`) values ($id, '" . addslashes($varbin) . "')";
        $r[] = true;
        $sql[] = "select `id`, `varbin` from `type_test` where id = $id";
        $r[] = [["id" => $id, "varbin" => $varbin] ];
        $this->sql = $sql;
        $this->r = $r;
    }

    public function sql()
    {
        $sql = array_shift($this->sql);
        $r = array_shift($this->r);
        if ($sql) {
            swoole_mysql_query(/*$this->swoole_mysql, */$sql, function($mysql, $result) use($sql, $r) {
                assert($result === $r);
                echo $sql, "\n";
                var_dump($r);
                echo "\n\n\n";
                $this->sql();
            });
        } else {
            swoole_event_exit();
        }
    }
}

(new Mysql())->sql();

<?php


define("MAX_UNSIGNED_BIGINT", "18446744073709551615");
define("MYSQL_SERVER_HOST", "127.0.0.1");
define("MYSQL_SERVER_PORT", 3306);
define("MYSQL_SERVER_USER", "test_database");
define("MYSQL_SERVER_PWD", "test_database");
define("MYSQL_SERVER_DB", "test_database");


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



function swoole_mysql_query($sql, callable $onQuery)
{
    $swoole_mysql = new \swoole_mysql();

    $swoole_mysql->on("close", function() {
        echo "closed\n";
    });

    $swoole_mysql->conn_timeout = swoole_timer_after(1000, function() use($onQuery, $swoole_mysql) {
        $onQuery($swoole_mysql, "connecte timeout");
    });

    $swoole_mysql->connect([
        "host" => MYSQL_SERVER_HOST,
        "port" => MYSQL_SERVER_PORT,
        "user" => MYSQL_SERVER_USER,
        "password" => MYSQL_SERVER_PWD,
        "database" => MYSQL_SERVER_DB,
        "charset" => "utf8mb4",
    ], function(\swoole_mysql $swoole_mysql, $result) use($sql, $onQuery, $swoole_mysql) {
        swoole_timer_clear($swoole_mysql->conn_timeout);

        if ($result) {
            $swoole_mysql->query_timeout = swoole_timer_after(1000, function() use($onQuery, $swoole_mysql) {
                $onQuery($swoole_mysql, "query timeout");
            });

            $swoole_mysql->query($sql, function(\swoole_mysql $swoole_mysql, $result) use($onQuery) {
                swoole_timer_clear($swoole_mysql->query_timeout);
                // TODO error error_no
                $onQuery($swoole_mysql, $result);
                // $swoole_mysql->close();
            });
        } else {
            echo "connect error [errno=$swoole_mysql->connect_errno, error=$swoole_mysql->connect_error]";
        }
    });
}



(new Mysql())->sql();

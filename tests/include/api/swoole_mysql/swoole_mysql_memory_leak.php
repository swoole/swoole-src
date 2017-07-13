<?php

// 轻微内存泄漏
//while (true) {
//    echo memory_get_usage(), "\n";
//    $pdo = new \PDO('swoole_mysql:dbname=test;host=127.0.0.1;port=3306', 'root', '123456');
//    $stmt = $pdo->prepare("select * from test");
//    $stmt->execute();
//    $r = $stmt->fetchAll(\PDO::FETCH_ASSOC);
//    // var_dump(count($r));
//}


$sql = "select * from component_v2";
define("MYSQL_SERVER_HOST", "127.0.0.1");
define("MYSQL_SERVER_PORT", 3306);
define("MYSQL_SERVER_USER", "test_database");
define("MYSQL_SERVER_PWD", "test_database");
define("MYSQL_SERVER_DB", "test_database");


//$sql = "select * from test";
//define("MYSQL_SERVER_HOST", "127.0.0.1");
//define("MYSQL_SERVER_PORT", 3306);
//define("MYSQL_SERVER_USER", "root");
//define("MYSQL_SERVER_PWD", "123456");
//define("MYSQL_SERVER_DB", "test");


class Callback
{
    public $sql;
    public $result;
    public function __construct($sql)
    {
        $this->sql = $sql;
    }
    public function __invoke($mysql, $result)
    {
        echo memory_get_usage(), "\n";
        $this->result = $result;
        $mysql->query($this->sql, new Callback($this->sql));
    }
}

$swoole_mysql = new \swoole_mysql();
$swoole_mysql->on("close", function() { echo "closed\n"; });
$swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
], function(\swoole_mysql $mysql) use($sql) {
    $mysql->query($sql, new Callback($sql));
});
<?php

require_once __DIR__ . "/swoole_mysql_init.php";

$sql = "select 1";
$bind = [];

$onQuery = function($mysql_result, $result) {
    var_dump($result);
    swoole_event_exit();
    fprintf(STDERR, "SUCCESS");
};

$swoole_mysql = new \swoole_mysql();

$swoole_mysql->on("connect", function(\swoole_mysql $swoole_mysql) use($sql, $bind, $onQuery, $swoole_mysql) {
//    $swoole_mysql->query($sql, $bind, swoole_function(\swoole_mysql $swoole_mysql, $result) use($onQuery) {
//        $onQuery($swoole_mysql, $result);
//         $swoole_mysql->close();
//    });
});

$swoole_mysql->on("error", function(\swoole_mysql $swoole_mysql) use($onQuery, $swoole_mysql) {
    $onQuery($swoole_mysql, "connection error");
});

$swoole_mysql->on("close", function() {
    echo "closed\n";
});


$swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
]);

// 未连上 直接 调用query
$r = $swoole_mysql->query($sql, $bind, function(\swoole_mysql $swoole_mysql, $result) use($onQuery) {
    var_dump("query cb");
    // TODO error error_no
    $onQuery($swoole_mysql, $result);
    // $swoole_mysql->close();
});

// 此处返回true 不符合预期
var_dump($r);
<?php

require_once __DIR__ . "/swoole_mysql_init.php";

function query($swoole_mysql, $dep = 0)
{

    $sql = "select 1";
    $swoole_mysql->query($sql, function(\swoole_mysql $swoole_mysql, $result) use($dep) {
    //    echo ".\n";
        if ($dep > 20) {
            fprintf(STDERR, "SUCCESS\n");
            swoole_event_exit();
        } else {
            if ($swoole_mysql->errno !== 0) {
                fprintf(STDERR, "FAIL");
                swoole_event_exit();
            } else {
                query($swoole_mysql, ++$dep);
            }
        }
    });
}

$swoole_mysql = new \swoole_mysql();
$swoole_mysql->on("close", function() {
   echo "closed\n";
});


$swoole_mysql->conn_timeout = swoole_timer_after(1000, function() {
    echo "connecte timeout\n\n\n";
});

$swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
], function(\swoole_mysql $swoole_mysql) {
    assert($swoole_mysql->errno === 0);
    swoole_timer_clear($swoole_mysql->conn_timeout);
    query($swoole_mysql);
});

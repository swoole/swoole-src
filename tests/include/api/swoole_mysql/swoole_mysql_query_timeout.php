<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

$swoole_mysql = new \swoole_mysql();

$swoole_mysql->on("close", function() {
    echo "closed\n";
    swoole_event_exit();
});

$swoole_mysql->on('timeout', function(\swoole_mysql $swoole_mysql, $timeoutType) {
    echo "connect timeout\n";
    assert($timeoutType === SWOOLE_ASYNC_CONNECT_TIMEOUT);
    $swoole_mysql->close();
});

$swoole_mysql->setConnectTimeout(5000);

$swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
], function(\swoole_mysql $swoole_mysql, $result) {
    if ($result) {
        $swoole_mysql->on("timeout", function(\swoole_mysql $swoole_mysql, $timeoutType) {
            echo "query timeout\n";
            assert($timeoutType === SWOOLE_ASYNC_RECV_TIMEOUT);
            $swoole_mysql->close();
        });

        $swoole_mysql->setQueryTimeout(1);

        $swoole_mysql->query("select sleep(1)", function(\swoole_mysql $swoole_mysql, $result) {
            assert(false);
            swoole_event_exit();
        });
    } else {
        echo "connect error [errno=$swoole_mysql->connect_errno, error=$swoole_mysql->connect_error]";
    }
});
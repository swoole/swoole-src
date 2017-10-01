<?php
$swoole_mysql = new \swoole_mysql();

$swoole_mysql->on("close", function ()
{
    echo "closed\n";
    swoole_event_exit();
});

$r = $swoole_mysql->connect([
    "host" => "11.11.11.11",
    "port" => 9000,
    "user" => "root",
    "password" => "admin",
    "database" => "test",
    "charset" => "utf8mb4",
    'timeout' => 1.0,
], function (\swoole_mysql $swoole_mysql, $result)
{
    assert($result === false);
});
<?php
require_once __DIR__ . "/../../../include/bootstrap.php";

$onQuery = function ($swoole_mysql, $result)
{
    assert($swoole_mysql->errno === 0);

    $swoole_mysql->query("select 1", function ($swoole_mysql, $result)
    {
        assert($swoole_mysql->errno === 0);
        echo "SUCCESS\n";
        swoole_event_exit();
    });
};

$sql = "show tables";
$swoole_mysql = new \swoole_mysql();

$swoole_mysql->on("close", function ()
{
    echo "closed\n";
});

$onConnect = function (\swoole_mysql $swoole_mysql, $result) use ($sql, $onQuery)
{
    if ($result)
    {
        $swoole_mysql->query_timeout = swoole_timer_after(1000, function () use ($onQuery, $swoole_mysql)
        {
            $onQuery($swoole_mysql, "query timeout");
        });

        $swoole_mysql->query($sql, function (\swoole_mysql $swoole_mysql, $result) use ($onQuery)
        {
            swoole_timer_clear($swoole_mysql->query_timeout);
            $onQuery($swoole_mysql, $result);
        });
    }
    else
    {
        echo "connect to swoole_mysql swoole_server[{$swoole_mysql->serverInfo['host']}:{$swoole_mysql->serverInfo['port']}] error [errno=$swoole_mysql->connect_errno, error=$swoole_mysql->connect_error]";
    }
};

$r = $swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
], $onConnect);
assert($r);

$r = @$swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
], $onConnect);
assert($r === false);

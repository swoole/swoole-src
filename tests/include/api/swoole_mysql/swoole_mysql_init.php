<?php
require_once __DIR__ . "/../../../include/bootstrap.php";

function swoole_mysql_query($sql, callable $onQuery)
{
    $mysql = new \swoole_mysql();

    $mysql->on("close", function ()
    {
        echo "closed\n";
    });

    $mysql->connect([
        "host" => MYSQL_SERVER_HOST,
        "port" => MYSQL_SERVER_PORT,
        "user" => MYSQL_SERVER_USER,
        "password" => MYSQL_SERVER_PWD,
        "database" => MYSQL_SERVER_DB,
        "charset" => "utf8mb4",
    ], function (\swoole_mysql $mysql, $result) use ($sql, $onQuery)
    {
        if ($result)
        {
            $mysql->query($sql, function (\swoole_mysql $swoole_mysql, $result) use ($onQuery)
            {
                $onQuery($swoole_mysql, $result);
            });
        }
        else
        {
            echo "connect error [errno=$mysql->connect_errno, error=$mysql->connect_error]";
        }
    });
}

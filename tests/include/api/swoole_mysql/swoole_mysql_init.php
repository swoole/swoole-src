<?php

require_once __DIR__ . "/../../../include/bootstrap.php";


function swoole_mariadb_query($sql, array $bind, callable $onQuery)
{
    $swoole_mysql = new \swoole_mysql();

    $swoole_mysql->on("connect", function(\swoole_mysql $swoole_mysql) use($sql, $bind, $onQuery) {
        swoole_timer_clear($swoole_mysql->conn_timeout);
        $swoole_mysql->query_timeout = swoole_timer_after(1000, function() use($onQuery, $swoole_mysql) {
            $onQuery($swoole_mysql, "query timeout");
        });

        $swoole_mysql->query($sql, $bind, function(\swoole_mysql $swoole_mysql, $result) use($onQuery) {
            swoole_timer_clear($swoole_mysql->query_timeout);
            // TODO error error_no
            $onQuery($swoole_mysql, $result);
            // $swoole_mysql->close();
        });
    });

    // $swoole_mysql->on("timeout", swoole_function(\swoole_mysql $swoole_mysql) {});

    $swoole_mysql->on("error", function(\swoole_mysql $swoole_mysql) use($onQuery) {
        $onQuery($swoole_mysql, "connection error");
    });

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
    ]);
}


function swoole_mysql_query($sql, callable $onQuery)
{
    $swoole_mysql = new \swoole_mysql();

    $swoole_mysql->on("close", function() {
        // echo "closed\n";
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
    ], function(\swoole_mysql $swoole_mysql, $result) use($sql, $onQuery) {
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

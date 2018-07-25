#!/usr/bin/env php
<?php

require __DIR__ . '/include/config.php';

go(function () {
    echo "[DB-init] initialization MySQL database...\n";
    $mysql = new Swoole\Coroutine\MySQL();
    $connected = $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ]);
    if (!$connected) {
        echo "[DB-init] Connect failed! Error#{$mysql->connect_errno}: {$mysql->connect_error}\n";
        exit(1);
    }
    if ($mysql->query(co::readFile(__DIR__ . '/test.sql'))) {
        echo "[DB-init] Done!\n";
    } else {
        echo "[DB-init] Failed! Error#{$mysql->errno}: {$mysql->error}\n";
        exit(1);
    }
});
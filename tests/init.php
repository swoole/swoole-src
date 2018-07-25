#!/usr/bin/env php
<?php
require __DIR__ . '/include/bootstrap.php';

echo "[DB-init] initialization MySQL database...\n";
try {
    $mysql = new PDO(
        "mysql:host=" . MYSQL_SERVER_HOST . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
        MYSQL_SERVER_USER, MYSQL_SERVER_PWD
    );
    if ($mysql->exec(file_get_contents(__DIR__ . '/test.sql'))) {
        echo "[DB-init] Done!\n";
    } else {
        echo "[DB-init] Failed! Error#{$mysql->errorCode()}: {$mysql->errorInfo()}\n";
        exit(1);
    }
} catch (\Exception $e) {
    echo "[DB-init] Connect failed! Error#{$e->getCode()}: {$e->getMessage()}\n";
    exit(1);
}
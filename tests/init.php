#!/usr/bin/env php
<?php
require __DIR__ . '/include/bootstrap.php';

echo "[DB-init] initialization MySQL database...\n";
try {
    $mysql = new PDO(
        "mysql:host=" . MYSQL_SERVER_HOST . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
        MYSQL_SERVER_USER, MYSQL_SERVER_PWD
    );
    $mysql->exec(file_get_contents(__DIR__ . '/test.sql'));
    if ($mysql->errorCode() > 0) {
        echo "[DB-init] Failed! Error#{$mysql->errorCode()}: \n" . var_dump_return($mysql->errorInfo()) . "\n";
        exit(1);
    } else {
        echo "[DB-init] Done!\n";
    }
} catch (\Exception $e) {
    echo "[DB-init] Connect failed! Error#{$e->getCode()}: {$e->getMessage()}\n";
    exit(1);
}
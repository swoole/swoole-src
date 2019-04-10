--TEST--
swoole_mysql_coro: invalid host
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $mysql = new Co\MySQL;
    $connected = $mysql->connect([
        'host' => 'invalid_host_' . get_safe_random(),
        'port' => MYSQL_SERVER_PORT,
        'database' => MYSQL_SERVER_DB,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'timeout' => 0.5
    ]);
    echo 'Connection: ' . ($connected ? 'Connected' : 'Not connected') . PHP_EOL;
    if (is_musl_libc()) {
        Assert::eq($mysql->connect_errno, SOCKET_EINVAL);
        Assert::eq($mysql->connect_error, swoole_strerror(SOCKET_EINVAL));
    } else {
        Assert::eq($mysql->connect_errno, SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        Assert::eq($mysql->connect_error, swoole_strerror(SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED));
    }
});
?>
--EXPECT--
Connection: Not connected

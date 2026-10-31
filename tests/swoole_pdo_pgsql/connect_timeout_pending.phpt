--TEST--
swoole_pdo_pgsql: connect timeout while TCP connection is pending
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

$connect = static function (): void {
    $context = stream_context_create(['socket' => ['backlog' => 1]]);
    $server = stream_socket_server(
        'tcp://127.0.0.1:0',
        $errno,
        $error,
        STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
        $context
    );
    $address = stream_socket_get_name($server, false);
    [$host, $port] = explode(':', $address, 2);

    $fillers = [];
    for ($index = 0; $index < 2; ++$index) {
        $fillers[] = stream_socket_client('tcp://' . $address, $errno, $error, 1);
        Assert::notEmpty($fillers[$index]);
    }

    $start = microtime(true);
    try {
        new PDO(
            "pgsql:host={$host};port={$port};dbname=test;sslmode=disable",
            'user',
            'pass',
            [PDO::ATTR_TIMEOUT => 1]
        );
    } catch (PDOException $exception) {
        $elapsed = microtime(true) - $start;
        Assert::same($exception->errorInfo[0], '08006');
        Assert::greaterThanEq($elapsed, 1);
        Assert::lessThan($elapsed, 3);
        echo "timeout\n";
    }

    foreach ($fillers as $filler) {
        fclose($filler);
    }
    fclose($server);
};

$connect();
Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
Co\run($connect);
?>
--EXPECT--
timeout
timeout

--TEST--
swoole_pdo_pgsql: fail over when a pending TCP connection is refused
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
skip_if_function_not_exist('pcntl_fork');
?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

$connect = static function (bool $hooked): void {
    $context = stream_context_create(['socket' => ['backlog' => 1]]);
    $first = stream_socket_server(
        'tcp://127.0.0.1:0',
        $errno,
        $error,
        STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
        $context
    );
    $second = stream_socket_server('tcp://127.0.0.1:0');
    $firstAddress = stream_socket_get_name($first, false);
    $secondAddress = stream_socket_get_name($second, false);

    $fillers = [];
    for ($index = 0; $index < 2; ++$index) {
        $fillers[] = stream_socket_client('tcp://' . $firstAddress, $errno, $error, 1);
        Assert::notEmpty($fillers[$index]);
    }

    $serverPid = pcntl_fork();
    if ($serverPid === 0) {
        usleep(400_000);
        foreach ($fillers as $filler) {
            fclose($filler);
        }
        fclose($first);

        $client = stream_socket_accept($second, 5);
        if (!$client || fread($client, 8192) === false) {
            exit(1);
        }
        fwrite($client, "R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I");
        fclose($client);
        fclose($second);
        exit(0);
    }
    Assert::greaterThan($serverPid, 0);

    foreach ($fillers as $filler) {
        fclose($filler);
    }
    fclose($first);
    fclose($second);

    [, $firstPort] = explode(':', $firstAddress, 2);
    [, $secondPort] = explode(':', $secondAddress, 2);
    $dsn = "pgsql:host=127.0.0.1,127.0.0.1;port={$firstPort},{$secondPort};dbname=test;sslmode=disable";
    $run = static function () use ($dsn): void {
        new PDO($dsn, 'user', 'pass', [PDO::ATTR_TIMEOUT => 5]);
        echo "connected\n";
    };

    if ($hooked) {
        Co\run($run);
    } else {
        $run();
    }

    pcntl_waitpid($serverPid, $status);
    Assert::true(pcntl_wifexited($status));
    Assert::same(pcntl_wexitstatus($status), 0);
};

$connect(false);
$connect(true);
?>
--EXPECT--
connected
connected

--TEST--
swoole_pdo_pgsql: blocking connect timeout survives interrupted polls
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('pcntl_signal');
skip_if_function_not_exist('posix_kill');
?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);

pcntl_signal(SIGUSR1, static function (): void {});

$parentPid = getmypid();
$signalerPid = pcntl_fork();
if ($signalerPid === 0) {
    $deadline = microtime(true) + 4;
    while (microtime(true) < $deadline) {
        posix_kill($parentPid, SIGUSR1);
        usleep(20_000);
    }
    exit(0);
}
Assert::greaterThan($signalerPid, 0);

$start = microtime(true);
try {
    new PDO(
        "pgsql:host=127.0.0.1;port={$port};dbname=test;sslmode=disable",
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

posix_kill($signalerPid, SIGTERM);
pcntl_waitpid($signalerPid, $status);
fclose($server);
?>
--EXPECT--
timeout

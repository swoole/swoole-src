--TEST--
swoole_pdo_pgsql: connect timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

// The server accepts the TCP connection but never answers the startup packet.
$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($server, false))[1];

$connect = static function () use ($port): void {
    $start = microtime(true);
    try {
        new PDO("pgsql:host=127.0.0.1;port={$port};dbname=test", 'user', 'pass', [PDO::ATTR_TIMEOUT => 1]);
    } catch (PDOException $e) {
        Assert::eq($e->errorInfo[0], '08006');
        Assert::greaterThanEq(microtime(true) - $start, 1);
        echo "timeout\n";
    }
};

$connect();
Co\run($connect);
?>
--EXPECT--
timeout
timeout

--TEST--
swoole_pdo_pgsql: connect timeout applies to each host address
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager();

$pm->parentFunc = static function () use ($pm): void {
    $dsn = sprintf(
        'pgsql:host=cluster.example,cluster.example;hostaddr=127.0.0.1,127.0.0.2;port=%d;dbname=test;sslmode=disable',
        $pm->getFreePort()
    );
    $connect = static function () use ($dsn): void {
        new PDO($dsn, 'user', 'pass', [PDO::ATTR_TIMEOUT => 2]);
        echo "connected\n";
    };

    $connect();
    Co\run($connect);
};

$pm->childFunc = static function () use ($pm): void {
    $server = stream_socket_server('tcp://0.0.0.0:' . $pm->getFreePort());
    $pm->wakeup();

    for ($i = 0; $i < 2; $i++) {
        $first = stream_socket_accept($server, 5);
        Assert::notEmpty(fread($first, 8192));
        usleep(1_600_000);
        $fields = "SFATAL\0C57P03\0Mthe database system is starting up\0\0";
        fwrite($first, 'E' . pack('N', strlen($fields) + 4) . $fields);
        fclose($first);

        $second = stream_socket_accept($server, 5);
        Assert::notEmpty(fread($second, 8192));
        usleep(1_000_000);
        fwrite($second, "R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I");
        fclose($second);
    }
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
connected
connected

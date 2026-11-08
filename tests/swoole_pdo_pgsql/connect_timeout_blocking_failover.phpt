--TEST--
swoole_pdo_pgsql: blocking connections skip a silent host after connect_timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager();
$pm->initFreePorts(2);

$pm->parentFunc = static function () use ($pm): void {
    $dsn = sprintf(
        'pgsql:host=127.0.0.1,127.0.0.1;port=%d,%d;dbname=test;sslmode=disable',
        $pm->getFreePort(0),
        $pm->getFreePort(1)
    );
    $connect = static function () use ($dsn): void {
        new PDO($dsn, 'user', 'pass', [PDO::ATTR_TIMEOUT => 2]);
        echo "connected\n";
    };

    Swoole\Runtime::enableCoroutine(0);
    Co\run($connect);

    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
    $connect();
};

$pm->childFunc = static function () use ($pm): void {
    // Keep the first listener open without answering the startup packet.
    $first = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort(0));
    $second = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort(1));
    $pm->wakeup();

    for ($attempt = 0; $attempt < 2; $attempt++) {
        $client = stream_socket_accept($second, 10);
        Assert::notEmpty(fread($client, 8192));
        // AuthenticationOk followed by ReadyForQuery.
        fwrite($client, "R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I");
        fclose($client);
    }

    fclose($first);
    fclose($second);
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
connected
connected

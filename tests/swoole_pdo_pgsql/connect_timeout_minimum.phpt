--TEST--
swoole_pdo_pgsql: preserve the libpq connect timeout minimum
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager();

$pm->parentFunc = static function () use ($pm): void {
    $dsn = sprintf(
        'pgsql:host=127.0.0.1;port=%d;dbname=test;sslmode=disable',
        $pm->getFreePort()
    );

    // Use an immediate successful connection to read the linked libpq version.
    $libpqMajor = (int) (new PDO($dsn, 'user', 'pass', [PDO::ATTR_TIMEOUT => 2]))
        ->getAttribute(PDO::ATTR_CLIENT_VERSION);

    $connect = static function () use ($dsn, $libpqMajor): void {
        try {
            new PDO($dsn, 'user', 'pass', [PDO::ATTR_TIMEOUT => 1]);
            $connected = true;
        } catch (PDOException $e) {
            Assert::same($e->errorInfo[0], '08006');
            $connected = false;
        }

        Assert::same($connected, $libpqMajor < 17);
        echo "compatible\n";
    };

    $connect();
    Co\run($connect);
};

$pm->childFunc = static function () use ($pm): void {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();

    foreach ([0, 1.5, 1.5] as $delay) {
        $client = stream_socket_accept($server, 5);
        Assert::notEmpty(fread($client, 8192));
        usleep((int) ($delay * 1_000_000));
        fwrite($client, "R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I");
        fclose($client);
    }
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
compatible
compatible

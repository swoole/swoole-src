--TEST--
swoole_pdo_pgsql: allow delayed rejection within the multi-host connection budget
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_libpq_version_lower_than(14);
?>
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
    new PDO($dsn, 'user', 'pass', [PDO::ATTR_TIMEOUT => 2]);
    echo "connected\n";

    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
    Co\run(static function () use ($dsn): void {
        $timerFired = false;
        Swoole\Timer::after(50, static function () use (&$timerFired): void {
            Assert::same(Swoole\Coroutine::stats()['aio_task_num'], 0);
            $timerFired = true;
        });
        new PDO($dsn, 'user', 'pass', [PDO::ATTR_TIMEOUT => 2]);
        Assert::true($timerFired);
        echo "connected\n";
    });
};
$pm->childFunc = static function () use ($pm): void {
    $firstServer = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort(0));
    $secondServer = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort(1));
    $pm->wakeup();
    for ($mode = 0; $mode < 2; $mode++) {
        $first = stream_socket_accept($firstServer, 10);
        Assert::notEmpty(fread($first, 8192));
        usleep(3_000_000);
        $fields = "SFATAL\0C57P03\0Mthe database system is starting up\0\0";
        fwrite($first, 'E' . pack('N', strlen($fields) + 4) . $fields);
        fclose($first);

        $second = stream_socket_accept($secondServer, 10);
        Assert::notEmpty(fread($second, 8192));
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

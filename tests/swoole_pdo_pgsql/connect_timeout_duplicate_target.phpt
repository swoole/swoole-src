--TEST--
swoole_pdo_pgsql: repeated targets retain the full connection budget
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_libpq_version_lower_than(14);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager();
$pm->parentFunc = static function () use ($pm): void {
    $dsn = sprintf(
        'pgsql:host=127.0.0.1,127.0.0.1;hostaddr=127.0.0.1,127.0.0.1;port=%d;dbname=test;sslmode=disable',
        $pm->getFreePort()
    );
    $connect = static function () use ($dsn): void {
        new PDO($dsn, 'user', 'pass', [PDO::ATTR_TIMEOUT => 3]);
        echo "connected\n";
    };
    $connect();
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
    Co\run($connect);
};
$pm->childFunc = static function () use ($pm): void {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    for ($mode = 0; $mode < 2; $mode++) {
        $first = stream_socket_accept($server, 10);
        Assert::notEmpty(fread($first, 8192));
        usleep(1_700_000);
        $fields = "SFATAL\0C57P03\0Mthe database system is starting up\0\0";
        fwrite($first, 'E' . pack('N', strlen($fields) + 4) . $fields);
        fclose($first);

        $second = stream_socket_accept($server, 10);
        Assert::notEmpty(fread($second, 8192));
        usleep(1_700_000);
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

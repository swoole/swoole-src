--TEST--
swoole_pdo_pgsql: wait cooperatively for ReadyForQuery without imposing a query timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/pgsql_test_server.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
    Swoole\Coroutine::set(['socket_read_timeout' => 0.05]);
    Swoole\Coroutine\run(function () use ($pm) {
        $pdo = new PDO(pgsql_test_dsn($pm->getFreePort()), 'user', 'pass', [PDO::ATTR_EMULATE_PREPARES => true]);
        $timerFired = false;
        Swoole\Timer::after(50, function () use (&$timerFired) {
            $timerFired = true;
        });
        Assert::eq($pdo->query('SELECT 1')->fetchColumn(), 1);
        Assert::true($timerFired, 'waiting for ReadyForQuery blocked the event loop');
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    $client = pgsql_test_accept($server);
    Assert::same(pgsql_test_read_message($client)[0], 'Q');
    fwrite($client, pgsql_test_result());
    usleep(300000);
    fwrite($client, pgsql_test_packet('Z', 'I'));
    usleep(100000);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE

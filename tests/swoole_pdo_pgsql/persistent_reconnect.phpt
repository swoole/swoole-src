--TEST--
swoole_pdo_pgsql: reset a disconnected persistent connection through asynchronous polling
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/pgsql_test_server.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
    Swoole\Coroutine\run(function () use ($pm) {
        $dsn = pgsql_test_dsn($pm->getFreePort());
        $options = [PDO::ATTR_PERSISTENT => true, PDO::ATTR_EMULATE_PREPARES => true];
        $pdo = new PDO($dsn, 'user', 'pass', $options);
        Assert::eq($pdo->query('SELECT 1')->fetchColumn(), 1);
        Swoole\Coroutine::sleep(0.05);
        $timerFired = false;
        Swoole\Timer::after(50, function () use (&$timerFired) {
            Assert::same(Swoole\Coroutine::stats()['aio_task_num'], 0);
            $timerFired = true;
        });
        $replacement = new PDO($dsn, 'user', 'pass', $options);
        Assert::true($timerFired, 'PQreset blocked the event loop');
        Assert::eq($replacement->query('SELECT 1')->fetchColumn(), 1);
        Assert::eq($pdo->query('SELECT 1')->fetchColumn(), 1);
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    $reply = pgsql_test_result() . pgsql_test_packet('Z', 'I');
    $first = pgsql_test_accept($server);
    Assert::same(pgsql_test_read_message($first)[0], 'Q');
    fwrite($first, $reply);
    fclose($first);

    $second = pgsql_test_accept($server, 300000);
    for ($i = 0; $i < 2; $i++) {
        Assert::same(pgsql_test_read_message($second)[0], 'Q');
        fwrite($second, $reply);
    }
    usleep(100000);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE

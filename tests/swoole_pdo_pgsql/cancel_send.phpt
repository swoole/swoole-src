--TEST--
swoole_pdo_pgsql: cancel a query while its output is blocked
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/pgsql_test_server.php';

foreach ([false, true] as $throw) {
    $pm = new ProcessManager;
    $pm->setWaitTimeout(3);
    $pm->parentFunc = function () use ($pm, $throw) {
        Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
        Swoole\Coroutine\run(function () use ($pm, $throw) {
            $pdo = new PDO(pgsql_test_dsn($pm->getFreePort()), 'user', 'pass', [PDO::ATTR_EMULATE_PREPARES => true]);
            $finished = false;
            $cid = go(function () use ($pdo, $throw, &$finished) {
                try {
                    $pdo->exec("SELECT '" . str_repeat('a', 16 * 1024 * 1024) . "'");
                    Assert::true(false, 'query returned after cancellation');
                } catch (Throwable $e) {
                    Assert::isInstanceOf($e, $throw ? Swoole\Coroutine\CanceledException::class : PDOException::class);
                    if (!$throw) {
                        Assert::notEmpty($e->getMessage());
                    }
                    $finished = true;
                }
            });
            // The peer has received the query header but deliberately stops draining the socket.
            Assert::true($pm->wait());
            Assert::true(Swoole\Coroutine::cancel($cid, $throw));
            Assert::true($finished);
            try {
                $pdo->query('SELECT 1');
                Assert::true(false, 'the interrupted connection was reused');
            } catch (PDOException $e) {
                Assert::same($e->getCode(), '08006');
            }
        });
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm) {
        $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
        $pm->wakeup();
        $client = pgsql_test_accept($server);
        Assert::same(pgsql_test_read_exact($client, 5)[0], 'Q');
        $pm->wakeup();
        sleep(5);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE

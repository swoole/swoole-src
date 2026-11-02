--TEST--
swoole_pdo_pgsql: canceled persistent connections are discarded without a blocking reset
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/pgsql_test_server.php';

foreach ([false, true] as $throw) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm, $throw) {
        Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
        Swoole\Coroutine\run(function () use ($pm, $throw) {
            $dsn = pgsql_test_dsn($pm->getFreePort());
            $options = [PDO::ATTR_PERSISTENT => true, PDO::ATTR_EMULATE_PREPARES => true];
            $pdo = new PDO($dsn, 'user', 'pass', $options);
            $alias = new PDO($dsn, 'user', 'pass', $options);
            $statement = $pdo->prepare('SELECT 1');
            $finished = false;
            $cid = go(function () use ($pdo, $throw, &$finished) {
                try {
                    $pdo->query('SELECT pg_sleep(5)');
                    Assert::true(false, 'query returned after cancellation');
                } catch (Throwable $e) {
                    Assert::isInstanceOf($e, $throw ? Swoole\Coroutine\CanceledException::class : PDOException::class);
                    $finished = true;
                }
            });
            Swoole\Coroutine::sleep(0.05);
            Assert::true(Swoole\Coroutine::cancel($cid, $throw));
            Assert::true($finished);

            $timerFired = false;
            Swoole\Timer::after(50, function () use (&$timerFired) {
                Assert::same(Swoole\Coroutine::stats()['aio_task_num'], 0);
                $timerFired = true;
            });
            $replacement = new PDO($dsn, 'user', 'pass', $options);
            Assert::true($timerFired, 'persistent checkout blocked the event loop');
            Assert::eq($replacement->query('SELECT 1')->fetchColumn(), 1);
            foreach ([$pdo, $alias] as $closed) {
                try {
                    $closed->query('SELECT 1');
                    Assert::true(false, 'the canceled handle was reused');
                } catch (PDOException $e) {
                    Assert::same($e->getCode(), '08006');
                }
            }
            try {
                $statement->execute();
                Assert::true(false, 'the statement reused a canceled connection');
            } catch (PDOException $e) {
                Assert::same($e->getCode(), '08006');
            }
            unset($closed, $pdo, $alias, $statement);
            Assert::eq($replacement->query('SELECT 1')->fetchColumn(), 1);
        });
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm) {
        $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
        $pm->wakeup();
        $first = pgsql_test_accept($server);
        Assert::same(pgsql_test_read_message($first)[0], 'Q');
        Assert::same(fread($first, 1), '');
        fclose($first);

        // Recovery must yield while the next startup response is delayed.
        $second = pgsql_test_accept($server, 300000);
        $reply = pgsql_test_result() . pgsql_test_packet('Z', 'I');
        for ($i = 0; $i < 2; $i++) {
            Assert::same(pgsql_test_read_message($second)[0], 'Q');
            fwrite($second, $reply);
        }
        usleep(100000);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE

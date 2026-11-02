--TEST--
swoole_pdo_pgsql: a terminal reactor registration error ends the result wait
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
skip('FFI is required to access the libpq socket', !extension_loaded('FFI'));
?>
--INI--
ffi.enable=1
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/pgsql_test_server.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
    Swoole\Coroutine::set(['log_level' => SWOOLE_LOG_ERROR]);
    Swoole\Coroutine\run(function () use ($pm) {
        $libpq = FFI::cdef('
            typedef struct pg_conn PGconn;
            typedef struct pg_result PGresult;
            PGconn *swoole_pgsql_connectdb(const char *conninfo);
            PGresult *swoole_pgsql_exec(PGconn *conn, const char *query);
            void swoole_pgsql_finish(PGconn *conn);
            int PQsocket(const PGconn *conn);
            int PQstatus(const PGconn *conn);
        ');
        $conn = $libpq->swoole_pgsql_connectdb('host=127.0.0.1 port=' . $pm->getFreePort()
            . ' dbname=test user=user sslmode=disable gssencmode=disable');
        $fd = $libpq->PQsocket($conn);
        Assert::greaterThanEq($fd, 0);
        // Occupy the fd in epoll so the query's own registration fails with EEXIST.
        Assert::same(Swoole\Event::add($fd, function () {}), $fd);
        $start = microtime(true);
        $result = $libpq->swoole_pgsql_exec($conn, 'SELECT 1');
        Assert::true($result === null || FFI::isNull($result));
        Assert::lessThan(microtime(true) - $start, 1);
        Assert::same($libpq->PQstatus($conn), 0, 'the low-level wait must leave disposal to PDO');
        Assert::true(Swoole\Event::del($fd));
        $libpq->swoole_pgsql_finish($conn);
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    $client = pgsql_test_accept($server);
    Assert::same(pgsql_test_read_message($client)[0], 'Q');
    sleep(5);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE

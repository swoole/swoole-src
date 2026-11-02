--TEST--
swoole_pdo_pgsql: cancel connect reports an error even when libpq has no message
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;

use function Swoole\Coroutine\run;

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(static function (): void {
    $server = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
    $cid = Coroutine::create(static function () use ($port): void {
        try {
            new PDO("pgsql:host=127.0.0.1;port={$port};dbname=test", 'test', 'test');
        } catch (PDOException $e) {
            Assert::contains($e->getMessage(), 'SQLSTATE[08006]');
            Assert::greaterThan(strlen($e->getMessage()), strlen('SQLSTATE[08006] [7] '));
            echo "canceled\n";
        }
    });
    $client = stream_socket_accept($server, 1);
    Assert::true(Coroutine::cancel($cid, true));
});
echo "DONE\n";
?>
--EXPECT--
canceled
DONE

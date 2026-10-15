--TEST--
swoole_server: wrong eof setting
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$options = ['package_eof' => '', 'open_eof_check' => true, 'open_eof_split' => true];
$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE);
try {
    $server->set($options);
    Assert::true(false, 'empty EOF must throw');
} catch (Swoole\Exception $exception) {
    Assert::contains($exception->getMessage(), 'package_eof cannot be an empty string');
}
Swoole\Coroutine\run(function () use ($options) {
    $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    Assert::true($client->set($options));
    try {
        $client->connect('127.0.0.1', 1);
        Assert::true(false, 'empty EOF must throw before connecting');
    } catch (Swoole\Exception $exception) {
        Assert::contains($exception->getMessage(), 'package_eof cannot be an empty string');
    }
    Assert::false($client->isConnected());
});
echo "DONE\n";
?>
--EXPECT--
DONE

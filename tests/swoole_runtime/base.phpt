--TEST--
swoole_runtime: base
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$server = SwooleTest\CoServer::createTcpGreeting();
$server->run();
Swoole\Runtime::enableCoroutine(true, SWOOLE_HOOK_ALL ^ SWOOLE_HOOK_SLEEP);
go(function () {
    usleep(1000);
    echo '1' . PHP_EOL;
});
echo '2' . PHP_EOL;
go(function () use ($server) {
    $cli = stream_socket_client("tcp://127.0.0.1:{$server->getPort()}", $errno, $errstr, 1);
    $read = $write = [$cli];
    $n = stream_select($read, $write, $except, 1);
    echo 'select' . PHP_EOL;
    Assert::same($n, 1);
    Assert::count($read, 1);
    Assert::count($write, 1);
    fread($cli, 8192);
    $n = stream_select($read, $write, $except, 1);
    Assert::same($n, 1);
    Assert::count($read, 0);
    Assert::count($write, 1);
});
echo '3' . PHP_EOL;
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL ^ SWOOLE_HOOK_FILE ^ SWOOLE_HOOK_STREAM_FUNCTION);
go(function () {
    $read = [fopen(__FILE__, 'r')];
    $n = stream_select($read, $write, $except, 1);
    Assert::same($n, 1);
    Assert::count($read, 1);
    echo '4' . PHP_EOL;
});
go(function () use ($server) {
    usleep(10 * 1000);
    echo 'sleep2' . PHP_EOL;
    $server->shutdown();
});
echo '5' . PHP_EOL;
Swoole\Runtime::enableCoroutine(true); // all
go(function () {
    usleep(5 * 1000);
    echo 'sleep1' . PHP_EOL;
});
echo '6' . PHP_EOL;
go(function () use ($server) {
    $read = [stream_socket_client("tcp://127.0.0.1:{$server->getPort()}", $errno, $errstr, 1)];
    $n = stream_select($read, $write, $except, 1);
    Assert::same($n, 1);
    Assert::count($read, 1);
    echo 'select' . PHP_EOL;
});
echo '7' . PHP_EOL;
Swoole\Event::wait();
Swoole\Runtime::enableCoroutine(false); // disable all
?>
--EXPECT--
1
2
3
4
5
6
7
select
select
sleep1
sleep2

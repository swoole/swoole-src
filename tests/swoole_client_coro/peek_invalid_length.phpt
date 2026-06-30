--TEST--
swoole_client_coro: peek rejects invalid length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client(SWOOLE_SOCK_UDP);
    $client->sendto('127.0.0.1', 1, 'x');
    var_dump($client->peek(0));
});
?>
--EXPECTF--
Warning: Swoole\Coroutine\Client::peek(): length must be greater than 0 in %s on line %d
bool(false)

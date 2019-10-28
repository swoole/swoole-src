--TEST--
swoole_http_client_coro: really keep alive
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('too slow');
if (getenv("SKIP_SLOW_TESTS")) {
    die("skip slow test");
}
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $cli = new Swoole\Coroutine\Http\Client('pecl.php.net', 443, true);
    $cli->set(['timeout' => 5]);
    Assert::assert($cli->get('/'));
    Assert::assert(strpos($cli->body, 'pecl') !== false);
    co::sleep(75);
    Assert::assert($cli->get('/'));
    Assert::assert(strpos($cli->body, 'pecl') !== false);
});
swoole_event_wait();
echo "OK\n";
?>
--EXPECT--
OK

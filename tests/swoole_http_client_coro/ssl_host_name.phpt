--TEST--
swoole_http_client_coro: https client with ssl_host_name
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $c = new Co\Http\Client('httpbin.org', 443, true);
    $c->set([
        'timeout' => 5,
        'ssl_host_name' => 'httpbin.org'
    ]);
    $c->get('/');
    Assert::assert(strlen($c->body) > 0);
    Assert::eq($c->statusCode, 200);
});
swoole_event::wait();
?>
--EXPECT--

--TEST--
swoole_http_client_coro: getHeaderOut after close
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $http = new Swoole\Coroutine\Http\Client('httpbin.org', 80, false);
    $http->set([
        'timeout' => -1,
        'keep_alive' => false,
    ]);
    $http->execute('/get');
    swoole_string($http->getHeaderOut())->contains('httpbin.org');
});
swoole_event::wait();

?>
--EXPECT--

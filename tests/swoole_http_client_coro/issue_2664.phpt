--TEST--
swoole_http_client_coro: set_cookie_headers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\Run(function () use ($pm) {
        var_dump(httpRequest("http://127.0.0.1:{$pm->getFreePort()}")['set_cookie_headers']);
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $time_left = time() + 84600;

        $cookie = new Swoole\Http\Cookie();
        $cookie->setName('key1');
        $cookie->setValue('val1');
        $cookie->setExpires($time_left);
        $cookie->setPath('/');
        $cookie->setDomain('id.test.com');
        $response->cookie($cookie);

        $cookie->setName('key1');
        $cookie->setValue('');
        $cookie->setExpires(0);
        $cookie->setPath('/');
        $cookie->setDomain('test.com');
        $response->cookie($cookie);

        $cookie->setName('key1');
        $cookie->setValue('val2');
        $cookie->setExpires($time_left);
        $cookie->setPath('/');
        $cookie->setDomain('id.test.com');
        $response->cookie($cookie);

        $cookie->setName('key2');
        $cookie->setValue('');
        $cookie->setExpires(0);
        $cookie->setPath('/');
        $cookie->setDomain('test.com');
        $response->cookie($cookie);

        $response->end("<h1>Hello Swoole. #" . rand(1000, 9999) . "</h1>");
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
array(4) {
  [0]=>
  string(91) "key1=val1; expires=%s; Max-Age=84600; path=/; domain=id.test.com"
  [1]=>
  string(62) "key1=deleted; expires=%s; Max-Age=0"
  [2]=>
  string(91) "key1=val2; expires=%s; Max-Age=84600; path=/; domain=id.test.com"
  [3]=>
  string(62) "key2=deleted; expires=%s; Max-Age=0"
}

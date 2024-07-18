--TEST--
swoole_http_cookie: new cookie
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
        $cookie = new Swoole\Http\Cookie();
        $cookie->setName('key1')
            ->setValue('val1')
            ->setExpires(time() + 84600)
            ->setPath('/')
            ->setDomain('id.test.com')
            ->setSecure(true)
            ->setHttpOnly(true)
            ->setSameSite('None')
            ->setPriority('High')
            ->setPartitioned(true);
        $response->setObjectCookie($cookie);
        $cookie->setValue('');
        $response->setObjectCookie($cookie);
        $response->end("<h1>Hello Swoole. #" . rand(1000, 9999) . "</h1>");
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
array(2) {
  [0]=>
  string(152) "key1=val1; expires=%s; Max-Age=84600; path=/; domain=id.test.com; secure; HttpOnly; SameSite=None; Priority=High; Partitioned"
  [1]=>
  string(62) "key1=deleted; expires=%s; Max-Age=0"
}

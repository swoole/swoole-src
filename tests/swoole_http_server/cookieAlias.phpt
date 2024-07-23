--TEST--
swoole_http_cookie: cookie alias
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
        $cookie->withName('key1')
            ->withValue('val1')
            ->withExpires(time() + 84600)
            ->withPath('/')
            ->withDomain('id.test.com')
            ->withSecure(true)
            ->withHttpOnly(true)
            ->withSameSite('None')
            ->withPriority('High')
            ->withPartitioned(true);
        $response->setCookie($cookie);
        $response->setCookie('key1', 'val1', time() + 84600, '/', 'id.test.com', true, true, 'None', 'High', true);
        $response->setRawCookie('key1', 'val1', time() + 84600, '/', 'id.test.com', true, true, 'None', 'High', true);

        $cookie->withValue('');
        $response->setCookie($cookie);
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
  string(152) "key1=val1; expires=%s; Max-Age=84600; path=/; domain=id.test.com; secure; HttpOnly; SameSite=None; Priority=High; Partitioned"
  [1]=>
  string(152) "key1=val1; expires=%s; path=/; domain=id.test.com; secure; HttpOnly; SameSite=None; Priority=High; Partitioned"
  [2]=>
  string(152) "key1=val1; expires=%s; Max-Age=84600; path=/; domain=id.test.com; secure; HttpOnly; SameSite=None; Priority=High; Partitioned"
  [3]=>
  string(62) "key1=deleted; expires=%s; Max-Age=0"
}

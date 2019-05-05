--TEST--
swoole_http_client_coro: http client set basic auth
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function(){
    $cli = new Swoole\Coroutine\Http\Client('httpbin.org');
    $cli->set(['timeout' => 10]);
    $cli->setHeaders([
        'host' => 'httpbin.org',
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $cli->setBasicAuth('username','password');
    $ret = $cli->get('/basic-auth/username/password');
    if($ret && !empty($cli->body)) echo("OK\n");
});
?>
--EXPECT--
OK

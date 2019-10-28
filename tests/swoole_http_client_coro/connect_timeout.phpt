--TEST--
swoole_http_client_coro: connect timeout
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $cli = new Swoole\Coroutine\Http\Client('140.207.135.104', 99, true);
    $cli->setHeaders([
        'Host' => "login.wx.qq.com",
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $random_timeout = mt_rand(100, 1000) / 1000;
    phpt_var_dump($random_timeout);
    $cli->set(['connect_timeout' => $random_timeout]);
    $s = microtime(true);
    $cli->get('/');
    $s = microtime(true) - $s;
    time_approximate($random_timeout, $s);
    echo $cli->body;
    $cli->close();
});

?>
--EXPECT--

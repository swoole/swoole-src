--TEST--
swoole_http_client_coro: recv timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$GLOBALS['socket'] = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
$GLOBALS['socket']->bind('127.0.0.1');
$GLOBALS['socket']->listen();
$GLOBALS['port'] = (int)$GLOBALS['socket']->getsockname()['port'];
go(function () {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        $conn = $GLOBALS['socket']->accept();
        Assert::assert($conn instanceof Co\Socket);
        $GLOBALS['connections'][] = $conn;
    }
});
for ($c = MAX_CONCURRENCY_MID; $c--;) {
    go(function () {
        $cli = new Co\Http\Client('127.0.0.1', $GLOBALS['port']);
        $cli->setDefer();
        $config_timeout = mt_rand(100, 500) / 1000;
        $cli->set(['timeout' => $config_timeout]);
        Assert::assert($cli->get('/'));
        $arg_timeout = mt_rand(100, 500) / 1000;
        $s = microtime(true);
        if (mt_rand(0, 1)) {
            $ret = $cli->recv();
            time_approximate($config_timeout, microtime(true) - $s);
        } else {
            $ret = $cli->recv($arg_timeout);
            time_approximate($arg_timeout, microtime(true) - $s);
        }
        Assert::assert(!$ret);
        Assert::assert($cli->errCode === SOCKET_ETIMEDOUT);
    });
}
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE

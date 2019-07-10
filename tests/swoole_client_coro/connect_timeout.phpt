--TEST--
swoole_client_coro: connect timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    co::set([
        'socket_connect_timeout' => 0.1
    ]);
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    $s = microtime(true);
    Assert::assert(!@$cli->connect('140.207.135.104', 1));
    Assert::same($cli->errCode, SOCKET_ETIMEDOUT);
    $s = microtime(true) - $s;
    phpt_var_dump($s);
    time_approximate($s, 0.1);
    $s = microtime(true);
    Assert::assert(!@$cli->connect('140.207.135.104', 1, $random_timeout = mt_rand(100, 1000) / 1000));
    Assert::same($cli->errCode, SOCKET_ETIMEDOUT);
    $s = microtime(true) - $s;
    phpt_var_dump($s);
    time_approximate($random_timeout, $s);
    echo "DONE\n";
});

?>
--EXPECT--
DONE

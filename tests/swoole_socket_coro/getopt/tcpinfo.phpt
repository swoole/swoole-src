--TEST--
swoole_socket_coro/getopt: tcp info
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require __DIR__ . '/../../include/api/http_test_cases.php';

use function Swoole\Coroutine\run;

run(function () {
    $content = http_get_with_co_socket('www.baidu.com', function ($cli, $content){
        $info = $cli->getOption(SOL_TCP, TCP_INFO);
        Assert::greaterThan($info['rcv_space'], 0);
        Assert::greaterThan($info['rto'], 0);
        Assert::greaterThan($info['rtt'], 0);
        Assert::greaterThan($info['snd_mss'], 0);
        Assert::greaterThan($info['rcv_mss'], 0);
        echo "DONE\n";
    });
    Assert::assert(strpos($content, 'map.baidu.com') !== false);
});
?>
--EXPECT--
DONE

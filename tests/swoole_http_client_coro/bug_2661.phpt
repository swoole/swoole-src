--TEST--
swoole_http_client_coro: #2611 bound error with dns resolve and cross close
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('travis network');
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine\Run(function () {
    $client = new Swoole\Coroutine\Http\Client('www.zhe800.com', 443, true);

    function foo($ch, $client)
    {
        mt_srand();
        $rand = mt_rand(100000, 999999999);
        $path = "/email_subscribe?email=" . $rand . "@" . substr(md5(microtime(true)), 0, 8) . ".com";
        $client->get($path);
        echo "push is " . $path . " " . Co::getCid() . "\n";
        $client->close();
        $ch->push($path);
    }

    function bar($client)
    {
        $length = 10;
        $ch = new Swoole\Coroutine\Channel($length);
        for ($i = 0; $i < $length; $i++) {
            go('foo', $ch, $client);
        }

        for ($i = 0; $i < $length; $i++) {
            go(function ($ch) {
                $data = $ch->pop(1);
                echo "pop is " . $data . "\n";
            }, $ch);
        }
    }

    bar($client);
});

?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: Socket#%d has already been bound to another coroutine#%d, reading or writing of the same socket in coroutine#%d at the same time is not allowed in %s:%d
Stack trace:
#0 %s(%d): Swoole\Coroutine\Http\Client->get('%s')
#1 {main}
  thrown in %s on line %d

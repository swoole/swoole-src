--TEST--
complete test: server&&client&&timeout(millisecond)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/swoole.inc';
$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    assert($socket instanceof Swoole\Coroutine\Socket);
    assert($socket->errCode === 0);
    go(function () use ($socket) {
        assert($socket->connect('localhost', 9501));
        $i = 0.000;
        while (true) {
            $socket->send("hello");
            $server_reply = $socket->recv(.01);
            assert($server_reply === 'swoole');
            co::sleep($i += .001); // after 10 times we sleep 0.01s to trigger server timeout
            if ($i > .01) {
                break;
            }
        }
        co::sleep(0.5);
        echo("client exit\n");
        $socket->close();
    });
    swoole_event_wait();
};

$pm->childFunc = function () use ($pm) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    assert($socket->bind('127.0.0.1', 9501));
    assert($socket->listen(128));
    go(function () use ($socket, $pm) {
        $client = $socket->accept();
        assert($client instanceof Swoole\Coroutine\Socket);
        $i = 0;
        while (true) {
            $client_data = $client->recv(.01);
            if ($client->errCode > 0) {
                assert($client->errCode === SOCKET_EAGAIN); //EAGAIN
                break;
            } else {
                $i++;
                assert($client_data === 'hello');
                $client->send('swoole');
            }
        }
        echo "$i\n";
        echo("sever exit\n");
        $client->close();
        $socket->close();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
10
sever exit
client exit

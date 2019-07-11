--TEST--
swoole_socket_coro: concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 100;

$socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
$socket->bind('127.0.0.1', 9601);
$socket->listen(128);

go(function () use ($socket)
{
    for ($i = 0; $i < N; $i++)
    {
        $client = $socket->accept();
        go(function () use ($client)
        {
            while (true)
            {
                $data = $client->recv();
                if (empty($data))
                {
                    $client->close();
                    break;
                }
                $client->send("Server: $data");
            }
        });
    }
});

for ($i = 0; $i < N; $i++)
{
    go(function ()
    {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $ret = $cli->connect('127.0.0.1', 9601);
        if ($ret)
        {
            $cli->send("hello\n");
            Assert::same($cli->recv(), 'Server: hello'."\n");
            $cli->close();
        }
        else
        {
            echo "ERROR\n";
        }
    });
}
swoole_event_wait();
?>
--EXPECT--

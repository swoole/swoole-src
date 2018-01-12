--TEST--
swoole_client: onBufferFull & onBufferEmpty

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$port = get_one_free_port();

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    Swoole\Async::set(['log_level' => 5, 'display_errors' => false]);
    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $client->set(['socket_buffer_size' => 1 * 1024 * 1024,]);
    $client->buffer = array();

    $client->on("connect", function (Swoole\Client $cli)
    {
        for ($i = 0; $i < 1024; $i++)
        {
            $data = str_repeat('A', 8192);
            if ($cli->send($data) === false and $cli->errCode == 1008) {
                $cli->buffer[] = $data;
            }
        }
    });

    $client->on("receive", function (Swoole\Client $cli, $data)
    {
        $cli->send(pack('N', 8) . 'shutdown');
        $cli->close();
        assert($data === md5_file(TEST_IMAGE));
    });

    $client->on("error", function($cli){
        echo "Connect failed\n";
    });

    $client->on("close", function($cli){

    });

    $client->on("bufferEmpty", function (Swoole\Client $cli)
    {
        echo "bufferEmpty\n";
        foreach ($cli->buffer as $k => $data)
        {
            if ($cli->send($data) === false and $cli->errCode == 1008)
            {
                break;
            }
            else
            {
                unset($cli->buffer[$k]);
            }
        }
        if (count($cli->buffer) == 0)
        {
            $cli->close();
        }
    });

    $client->on("bufferFull", function (Swoole\Client $cli)
    {
        echo "bufferFull\n";
    });

    $client->connect(TCP_SERVER_HOST, $port, 0.5);
    Swoole\Event::wait();
};

$pm->childFunc = function () use ($pm, $port)
{
    $socket = stream_socket_server("tcp://0.0.0.0:{$port}", $errno, $errstr) or die("$errstr ($errno)<br />\n");
    $pm->wakeup();
    while ($conn = stream_socket_accept($socket))
    {
        for ($i = 0; $i < 4; $i++)
        {
            usleep(500000);
            for ($j = 0; $j < 256; $j++)
            {
                $data = fread($conn, 8192);
            }
        }
        fclose($conn);
        break;
    }
    fclose($socket);
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
bufferFull
bufferEmpty
bufferFull
bufferEmpty
bufferFull
bufferEmpty
bufferFull
bufferEmpty

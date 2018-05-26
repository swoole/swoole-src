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

    $has_empty = false;
    $client->on("bufferEmpty", function (Swoole\Client $cli) use (&$has_empty)
    {
        if (!$has_empty)
        {
            echo "bufferEmpty\n";
            $has_empty = true;
        }
        while ($data = array_shift($cli->buffer)){
            if ($cli->send($data) === false && $cli->errCode == 1008)
            {
                $cli->buffer[] = $data;
                return;
            }
        }
        $cli->close();
    });

    $has_full = false;
    $client->on("bufferFull", function (Swoole\Client $cli) use (&$has_full)
    {
        if (!$has_full)
        {
            echo "bufferFull\n";
            $has_full = true;
        }
    });

    $client->connect(TCP_SERVER_HOST, $port, 0.5);
    Swoole\Event::wait();
};

$pm->childFunc = function () use ($pm, $port)
{
    $socket = stream_socket_server("tcp://0.0.0.0:{$port}", $errno, $errstr) or die("$errstr ($errno)<br />\n");
    $pm->wakeup();
    $count = 0;
    while ($conn = stream_socket_accept($socket))
    {
        for ($i = 0; $i < 4; $i++)
        {
            for ($j = 0; $j < 256; $j++)
            {
                fread($conn, 8192);
                $count++;
            }
            usleep(10 * 1000); // simulate block
        }
        fclose($conn);
        break;
    }
    assert($count === 1024); // to ensure all data has received.
    fclose($socket);
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
bufferFull
bufferEmpty

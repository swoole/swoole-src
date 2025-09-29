--TEST--
swoole_client_async: onBufferFull & onBufferEmpty
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Async\Client;

$port = get_one_free_port();

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port) {
    Co::set(['log_level' => 5, 'display_errors' => false]);
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set(['socket_buffer_size' => 1 * 1024 * 1024,]);
    $client->buffer = array();

    $countBufferEmpty = 0;
    $countBufferFull = 0;

    $client->on("connect", function (Client $cli) {
        for ($i = 0; $i < 1024; $i++) {
            $data = str_repeat('A', 8192);
            if ($cli->send($data) === false and $cli->errCode == 1008) {
                $cli->buffer[] = $data;
            }
        }
    });

    $client->on("receive", function (Client $cli, $data) {
        $cli->send(pack('N', 8) . 'shutdown');
        $cli->close();
        Assert::same($data, md5_file(TEST_IMAGE));
    });

    $client->on("error", function ($cli) {
        echo "Connect failed\n";
    });

    $client->on("close", function ($cli) {

    });

    $client->on("bufferEmpty", function (Client $cli) use (&$countBufferEmpty) {
        $countBufferEmpty++;
        foreach ($cli->buffer as $k => $data) {
            if ($cli->send($data) === false and $cli->errCode == 1008) {
                break;
            } else {
                unset($cli->buffer[$k]);
            }
        }
        if (count($cli->buffer) == 0) {
            $cli->close();
        }
    });

    $client->on("bufferFull", function (Client $cli) use (&$countBufferFull) {
        $countBufferFull++;
    });

    $client->connect(TCP_SERVER_HOST, $port, 0.5);
    Swoole\Event::wait();

    Assert::greaterThanEq($countBufferEmpty, 1);
    Assert::greaterThanEq($countBufferFull, 1);
};

$pm->childFunc = function () use ($pm, $port) {
    $socket = stream_socket_server("tcp://0.0.0.0:{$port}", $errno, $errstr) or die("$errstr ($errno)<br />\n");
    $pm->wakeup();
    while ($conn = stream_socket_accept($socket)) {
        for ($i = 0; $i < 4; $i++) {
            usleep(500000);
            for ($j = 0; $j < 256; $j++) {
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


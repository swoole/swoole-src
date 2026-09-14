--TEST--
swoole_http2_server: reject invalid peer maximum frame sizes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId & 0x7fffffff)
        . $payload;
}

$pm = new ProcessManager;
$invalidValues = [0, 16777216];

$pm->parentFunc = function () use ($pm, $invalidValues) {
    foreach ($invalidValues as $value) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        $client->set(['timeout' => 0.2]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));

        $preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        $settings = http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0, pack('nN', 5, $value));
        $request = $preface . $settings;
        Assert::same($client->send($request), strlen($request));

        $closed = false;
        for ($i = 0; $i < 3; $i++) {
            $data = $client->recv();
            if ($data === '') {
                $closed = true;
                break;
            }
            if ($data === false) {
                break;
            }
        }
        Assert::true($closed);
        $client->close();
    }

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end();
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE

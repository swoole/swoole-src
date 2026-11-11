--TEST--
swoole_http2_server: close the connection when a header block can't be sent
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;

// The server's HPACK table now has entries the client never received, so the connection must end.
function read_until_closed($client): void
{
    while (http2_test_read_frame($client) !== false) {
    }
    Assert::true(feof($client));
}

// Stream 1 fills the connection, so stream 3's header block waits for it.
function fill_connection($response): void
{
    for ($i = 0; $i < 16384; $i++) {
        if (!$response->write(str_repeat('A', 2048))) {
            break;
        }
    }
    // Ending stream 1 could close the connection by itself.
    (new Channel(1))->pop();
}

$cases = [
    // The response headers' writer is cancelled while it waits.
    'header' => [
        function (ProcessManager $pm, $client) {
            fwrite($client, http2_test_request_headers(3, '/'));
            Assert::true($pm->wait());
            read_until_closed($client);
        },
        function (Swoole\Http\Server $server, ProcessManager $pm) {
            $go = new Channel(1);
            $server->on('Request', function ($request, $response) use ($pm, $go) {
                if ($request->streamId === 1) {
                    Swoole\Event::defer(fn () => $go->push(true));
                    fill_connection($response);
                    return;
                }
                $go->pop();
                $cid = Coroutine::getCid();
                Swoole\Timer::after(100, fn () => Coroutine::cancel($cid, true));
                $response->header('x-test', 'header-value');
                try {
                    $response->end('x');
                } catch (Coroutine\CanceledException) {
                    echo "cancelled\n";
                }
                Assert::false($response->isWritable());
                $pm->wakeup();
            });
        },
    ],
    // The trailer times out after the client resets its stream.
    'trailer' => [
        function (ProcessManager $pm, $client) {
            fwrite($client, http2_test_request_headers(3, '/'));
            Assert::true($pm->wait());
            fwrite($client, http2_test_frame(3, 0, 3, pack('N', 8)));
            Assert::true($pm->wait());
            read_until_closed($client);
        },
        function (Swoole\Http\Server $server, ProcessManager $pm) {
            $server->set(['send_timeout' => 0.5]);
            $go1 = new Channel(1);
            $go3 = new Channel(1);
            $server->on('Request', function ($request, $response) use ($pm, $go1, $go3) {
                if ($request->streamId === 1) {
                    $go1->pop();
                    Swoole\Event::defer(fn () => $go3->push(true));
                    fill_connection($response);
                    return;
                }
                Assert::true($response->write('x'));
                $go1->push(true);
                $go3->pop();
                $response->trailer('x-test', 'trailer-value');
                $pm->wakeup();
                var_dump($response->end());
                $pm->wakeup();
            });
        },
    ],
];

foreach ($cases as $name => [$parent, $child]) {
    echo "{$name}\n";
    $pm = new ProcessManager();
    $pm->setWaitTimeout(5);
    $pm->parentFunc = function () use ($pm, $parent) {
        // The client doesn't read until stream 3's send has failed, so stream 1 fills the buffers.
        $client = http2_test_open_request($pm->getFreePort(), '/', 0x7FFFFFFF);
        try {
            $parent($pm, $client);
        } finally {
            fclose($client);
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $child) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
        $server->set([
            'log_file'            => '/dev/null',
            'open_http2_protocol' => true,
            'http_compression'    => false,
            'send_yield'          => true,
            'buffer_output_size'  => 1024 * 1024,
        ]);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('Close', function () {
            echo "closed\n";
        });
        $child($server, $pm);
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECT--
header
closed
cancelled
trailer
closed
bool(false)

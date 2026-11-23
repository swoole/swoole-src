--TEST--
swoole_http2_server_coro: streams take turns writing to the connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Event;

const CHUNK_SIZE = 1024 * 1024;

function connect(ProcessManager $pm): Client
{
    $cli = new Client('127.0.0.1', $pm->getFreePort());
    // Small buffers, so /big waits for the client to read
    $cli->set(['socket_buffer_size' => 65536]);
    Assert::true($cli->connect());
    // Complete the SETTINGS exchange before testing socket capacity. The client advertises large connection
    // and stream windows, so this test must wait on socket capacity rather than HTTP/2 flow control.
    send_request($cli, '/health');
    Assert::same($cli->recv(5)->data, 'OK');
    return $cli;
}

function send_request(Client $cli, string $path): void
{
    $request = new Swoole\Http2\Request;
    $request->path = $path;
    Assert::greaterThan($cli->send($request), 0);
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Coroutine::set(['http2_init_window_size' => 0x7fffffff]);
    go(function () use ($pm) {
        // While /big writes, the other responses and the PING ACK wait their turn
        $cli = connect($pm);
        send_request($cli, '/big');
        for ($id = 0; $id < 3; $id++) {
            send_request($cli, "/small?id={$id}");
        }
        send_request($cli, '/cancel?case=wait');
        // Its handler leaves the response to the destructor in the receive loop, which queues it behind /big
        send_request($cli, '/noend');
        Assert::true($cli->ping());
        $pm->wait();
        $responses = [];
        for ($n = 6; $n--;) {
            $response = $cli->recv(5);
            $responses[$response->streamId] = $response;
        }
        Assert::true($responses[3]->data !== '' && strspn($responses[3]->data, 'A') === strlen($responses[3]->data));
        for ($id = 0; $id < 3; $id++) {
            $response = $responses[5 + $id * 2];
            Assert::same($response->headers['x-id'], "{$id}");
            Assert::same($response->headers['x-trailer'], "{$id}");
            Assert::same($response->data, "small {$id}");
        }
        // The canceled end() encoded nothing, so the retried headers still decode
        Assert::same($responses[11]->headers['x-cancel'], 'value');
        Assert::same($responses[13]->statusCode, 500);
        Assert::same($responses[13]->headers['server'], 'swoole-http-server');
        $cli->close();

        // The peer goes away while one response writes and two wait
        $cli = connect($pm);
        send_request($cli, '/big?case=close');
        send_request($cli, '/small?case=close&id=0');
        send_request($cli, '/small?case=close&id=1');
        $pm->wait();
        $cli->close();

        // The writing response is canceled partway through a frame while another waits
        $partial = connect($pm);
        send_request($partial, '/big?case=cancel');
        send_request($partial, '/small?case=cancel&id=0');

        $cli = new Client('127.0.0.1', $pm->getFreePort());
        Assert::true($cli->connect());
        send_request($cli, '/results');
        echo $cli->recv(5)->data, "\n";
        $cli->close();
        $partial->close();
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        Coroutine::create(function () use ($pm) {
            $results = new Coroutine\Channel(6);
            $bigCid = 0;
            $http = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort());
            $http->set(['open_http2_protocol' => true, 'socket_buffer_size' => 4096]);
            $http->handle('/', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm, $results, &$bigCid) {
                $path = $request->server['request_uri'];
                $case = $request->get['case'] ?? null;
                // Deferred callbacks run once the handler's end() has started waiting for /big
                switch ($path) {
                    case '/health':
                        $response->end('OK');
                        return;
                    case '/big':
                        $bigCid = Coroutine::getCid();
                        // Write until a write has to wait for the client: the callback runs once this coroutine yields
                        $waited = false;
                        Event::defer(function () use (&$waited) {
                            $waited = true;
                        });
                        do {
                            $ok = $response->write(str_repeat('A', CHUNK_SIZE));
                        } while ($ok && !$waited);
                        $ok = $ok && $response->end();
                        break;
                    case '/small':
                        if ($case === 'cancel') {
                            $cid = $bigCid;
                            Event::defer(fn () => Coroutine::cancel($cid));
                        } elseif ($case === 'close' && $request->get['id'] === '1') {
                            Event::defer(fn () => $pm->wakeup());
                        }
                        $response->header('x-id', $request->get['id']);
                        $response->trailer('x-trailer', $request->get['id']);
                        // Writes take turns per frame. A short response can finish before the peer closes;
                        // make every close-case response large enough to remain blocked on socket capacity.
                        $body = $case === 'close' ? str_repeat('S', CHUNK_SIZE) : "small {$request->get['id']}";
                        $ok = $response->end($body);
                        break;
                    case '/cancel':
                        $cid = Coroutine::getCid();
                        Event::defer(function () use ($pm, $cid) {
                            Coroutine::cancel($cid);
                            // The retried end() is waiting again
                            $pm->wakeup();
                        });
                        $response->header('x-cancel', 'value');
                        $ok = $response->end();
                        $response->end();
                        break;
                    case '/results':
                        $lines = [];
                        for ($n = 6; $n--;) {
                            $lines[] = $results->pop(5);
                        }
                        sort($lines);
                        $response->end(implode("\n", $lines));
                        return;
                }
                if ($case) {
                    $results->push("{$case} {$path} " . var_export($ok, true));
                }
            });
            Event::defer(fn () => $pm->wakeup());
            $http->start();
        });
    });
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
cancel /big false
cancel /small false
close /big false
close /small false
close /small false
wait /cancel false

--TEST--
swoole_http2_client_coro: send requests while another request is being written
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;

// Connects through a proxy that doesn't read from the client until resumed, so the client's writes wait. Small
// socket buffers make them wait after the same amount of data whatever the system's TCP buffer settings are.
function connect_paused(ProcessManager $pm): array
{
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->setOption(SOL_SOCKET, SO_RCVBUF, 64 * 1024));
    Assert::true($listener->bind('127.0.0.1'));
    Assert::true($listener->listen());
    $port   = $listener->getsockname()['port'];
    $resume = new Channel(1);
    go(function () use ($listener, $pm, $resume) {
        $downstream = $listener->accept();
        $listener->close();
        $upstream = new Socket(AF_INET, SOCK_STREAM, 0);
        Assert::true($upstream->connect('127.0.0.1', $pm->getFreePort()));
        go(function () use ($downstream, $upstream, $resume) {
            $resume->pop();
            while (($data = $downstream->recv(65536, -1)) !== '' && $data !== false) {
                $upstream->sendAll($data);
            }
            $upstream->close();
        });
        while (($data = $upstream->recv(65536, -1)) !== '' && $data !== false) {
            $downstream->sendAll($data);
        }
        $downstream->close();
    });

    $client = new Client('127.0.0.1', $port);
    $client->set(['timeout' => USE_VALGRIND ? 120 : 10, 'socket_buffer_size' => 64 * 1024]);
    Assert::true($client->connect());
    return [$client, fn () => $resume->push(true)];
}

function create_request(string $path, array $headers = [], ?string $data = null): Request
{
    $request          = new Request();
    $request->path    = $path;
    $request->headers = $headers;
    if ($data !== null) {
        $request->method = 'POST';
        $request->data   = $data;
    }
    return $request;
}

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        // A request sent while another request's body waits gets its own stream, is queued whole, and a request
        // rejected because the queue is full doesn't change the connection's HPACK state.
        [$client, $resume] = connect_paused($pm);
        $big               = 0;
        go(function () use ($client, &$big) {
            $big = $client->send(create_request('/big', [], str_repeat('A', 16 * 1024 * 1024)));
        });
        $queued = $client->send(create_request('/queued', [], str_repeat('B', 4 * 1024 * 1024)));
        Assert::greaterThan($queued, 0);
        Assert::false($client->send(create_request('/rejected', ['x-test' => 'test-value'])));
        Assert::same($client->errCode, SWOOLE_ERROR_QUEUE_FULL);

        $resume();
        $responses = [];
        while (count($responses) < 2 && ($response = $client->recv())) {
            $responses[$response->streamId] = $response->data;
        }
        Assert::same($responses[$big] ?? null, (string) (16 * 1024 * 1024));
        Assert::same($responses[$queued] ?? null, (string) (4 * 1024 * 1024));
        Assert::greaterThan($client->send(create_request('/header', ['x-test' => 'test-value'])), 0);
        Assert::same($client->recv()->data, md5('test-value'));
        $client->close();

        // A request encoded while another request's HEADERS frame waits doesn't overwrite that frame.
        [$client, $resume] = connect_paused($pm);
        $expected          = [];
        $stop              = false;
        $sent              = new Channel(1);
        go(function () use ($client, &$expected, &$stop, $sent) {
            for ($i = 0; $i < 10000 && !$stop; $i++) {
                // Unique large values keep each header block large.
                $value = base64_encode(random_bytes(3000));
                $id    = $client->send(create_request('/header', ['x-test' => $value]));
                Assert::greaterThan($id, 0);
                $expected[$id] = md5($value);
            }
            $sent->push($stop);
        });
        $stop  = true;
        $value = base64_encode(random_bytes(3000));
        $id    = $client->send(create_request('/header', ['x-test' => $value]));
        Assert::greaterThan($id, 0);
        $expected[$id] = md5($value);

        $resume();
        Assert::true($sent->pop(), 'a HEADERS write must have been waiting');
        $responses = [];
        while (count($responses) < count($expected) && ($response = $client->recv())) {
            $responses[$response->streamId] = $response->data;
        }
        ksort($expected);
        ksort($responses);
        Assert::same($responses, $expected);
        $client->close();

        // Frames queued while a DATA frame's header waits are sent after its payload, not between them. Each write
        // sends a DATA frame with a 1-byte payload, so the wait usually lands on a frame header; repeat to make sure.
        for ($round = 0; $round < 5; $round++) {
            [$client, $resume] = connect_paused($pm);
            $request           = create_request('/pipeline', [], '');
            $request->pipeline = true;
            $pipeline          = $client->send($request);
            Assert::greaterThan($pipeline, 0);
            $written = 0;
            $stop    = false;
            $sent    = new Channel(1);
            go(function () use ($client, $pipeline, &$written, &$stop, $sent) {
                for ($i = 0; $i < 100000 && !$stop; $i++) {
                    Assert::true($client->write($pipeline, 'x'));
                    $written++;
                }
                $sent->push($stop);
            });
            $stop = true;
            $id   = $client->send(create_request('/header', ['x-test' => 'test-value']));
            Assert::greaterThan($id, 0);

            $resume();
            Assert::true($sent->pop(), 'a DATA write must have been waiting');
            Assert::true($client->write($pipeline, '', true));
            $responses = [];
            while (count($responses) < 2 && ($response = $client->recv())) {
                $responses[$response->streamId] = $response->data;
            }
            Assert::same($responses[$pipeline] ?? null, (string) $written);
            Assert::same($responses[$id] ?? null, md5('test-value'));
            $client->close();
        }
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file'            => '/dev/null',
        'open_http2_protocol' => true,
        'package_max_length'  => 32 * 1024 * 1024,
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) {
        if ($request->server['request_uri'] === '/header') {
            $response->end(md5($request->header['x-test']));
        } else {
            $response->end(strlen($request->rawContent()));
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE

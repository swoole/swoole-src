--TEST--
swoole_http2_server_coro: streams take turns writing to the connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;

// More than the connection can hold, so this response keeps writing until the client reads
const BODY_SIZE = 32 * 1024 * 1024;

function send_request(Client $cli, string $path): void
{
    $request = new Swoole\Http2\Request;
    $request->path = $path;
    Assert::greaterThan($cli->send($request), 0);
}

function cancel_soon(): void
{
    $cid = Coroutine::getCid();
    Coroutine::create(function () use ($cid) {
        Coroutine::sleep(0.1);
        Coroutine::cancel($cid);
    });
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Coroutine::set(['http2_init_window_size' => BODY_SIZE]);
    go(function () use ($pm) {
        // While /big writes, the other responses and the PING ACK wait their turn
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        Assert::true($cli->connect());
        send_request($cli, '/big');
        for ($id = 0; $id < 3; $id++) {
            send_request($cli, "/small?id={$id}");
        }
        send_request($cli, '/cancel?case=wait');
        Assert::true($cli->ping());
        Coroutine::sleep(0.5);
        $responses = [];
        for ($n = 5; $n--;) {
            $response = $cli->recv(5);
            $responses[$response->streamId] = $response;
        }
        Assert::true($responses[1]->data === str_repeat('A', BODY_SIZE));
        for ($id = 0; $id < 3; $id++) {
            $response = $responses[3 + $id * 2];
            Assert::same($response->headers['x-id'], "{$id}");
            Assert::same($response->headers['x-trailer'], "{$id}");
            Assert::same($response->data, "small {$id}");
        }
        // The canceled end() encoded nothing, so the retried headers still decode
        Assert::same($responses[9]->headers['x-cancel'], 'value');
        $cli->close();

        // The peer goes away while one response writes and two wait
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        Assert::true($cli->connect());
        send_request($cli, '/big?case=close');
        send_request($cli, '/small?case=close&id=0');
        send_request($cli, '/small?case=close&id=1');
        Coroutine::sleep(0.1);
        $cli->close();

        // The writing response is canceled partway through a frame while another waits
        $partial = new Client('127.0.0.1', $pm->getFreePort());
        Assert::true($partial->connect());
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
            $http = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort());
            $http->set(['open_http2_protocol' => true]);
            $http->handle('/', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($results) {
                $path = $request->server['request_uri'];
                $case = $request->get['case'] ?? null;
                switch ($path) {
                    case '/big':
                        if ($case === 'cancel') {
                            cancel_soon();
                        }
                        $ok = $response->end(str_repeat('A', BODY_SIZE));
                        break;
                    case '/small':
                        $response->header('x-id', $request->get['id']);
                        $response->trailer('x-trailer', $request->get['id']);
                        $ok = $response->end("small {$request->get['id']}");
                        break;
                    case '/cancel':
                        cancel_soon();
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
            $pm->wakeup();
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

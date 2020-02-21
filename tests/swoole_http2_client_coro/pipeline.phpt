--TEST--
swoole_http2_client_coro: pipeline
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->initRandomData(MAX_REQUESTS, 8);
$pm->parentFunc = function ($pid) use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->connect());
        /** @var $channels Swoole\Coroutine\Channel[] */
        $channels = [];
        for ($n = MAX_REQUESTS; $n--;) {
            $request = new Swoole\Http2\Request;
            $request->pipeline = true;
            $streamId = $client->send($request);
            if (Assert::greaterThan($streamId, 0)) {
                $data = $pm->getRandomData();
                for ($i = 0; $i < strlen($data); $i++) {
                    $client->write($streamId, $data[$i], $i === (strlen($data) - 1));
                }
                $channels[$streamId] = $channel = new Swoole\Coroutine\Channel;
                Swoole\Coroutine::create(function () use ($streamId, $channel, $data) {
                    /** @var $response Swoole\Http2\Response */
                    $response = $channel->pop();
                    $response->headers += ($channel->pop())->headers;
                    Assert::same($response->streamId, $streamId);
                    unset($response->headers['date']);
                    Assert::same($response->headers, [
                        'content-type' => 'application/srpc',
                        'trailer' => 'srpc-status, srpc-message',
                        'server' => 'swoole-http-server',
                        'content-length' => '8',
                        'srpc-status' => '0',
                        'srpc-message' => '',
                    ]);
                    Assert::same($response->data, $data);
                });
            }
        }
        while (true) {
            /** @var $response Swoole\Http2\Response */
            $response = $client->read();
            $channels[$response->streamId]->push($response);
            if (!$response->pipeline) {
                unset($channels[$response->streamId]);
            }
            if (empty($channels)) {
                break;
            }
        }
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $response->header('content-type', 'application/srpc');
        $response->header('trailer', 'srpc-status, srpc-message');
        $trailer = [
            "srpc-status" => '0',
            "srpc-message" => ''
        ];
        foreach ($trailer as $trailer_name => $trailer_value) {
            $response->trailer($trailer_name, $trailer_value);
        }
        $response->end($pm->getRandomData());
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE

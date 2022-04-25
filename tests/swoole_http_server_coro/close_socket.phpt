--TEST--
swoole_http_server_coro: close socket
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\System;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Coroutine\Http\Client;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        for ($i = 0; $i < 2; $i++) {
            $cli = new Client('127.0.0.1', $pm->getFreePort());
            Assert::assert($cli->get('/'));
            Assert::contains($cli->headers['server'], 'BWS');
        }
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort());
        $server->handle('/', function (Request $request, Response $response) {
            $response->detach();
            $socket = $response->socket;
            $headers = [];
            $checkHttpCode = false;
            $isHeaderSended = false;
            $httpCode = 200;

            $curl = curl_init();
            curl_setopt($curl, CURLOPT_URL, 'https://www.baidu.com/');
            curl_setopt($curl, CURLOPT_HEADERFUNCTION, function ($curl, $header) use (&$headers, &$httpCode, &$checkHttpCode) {
                if (!$checkHttpCode) {
                    $checkHttpCode = true;
                    preg_match('/HTTP\/[0-9.]+\s(\d+)\s(.*)/', $header, $matches, PREG_OFFSET_CAPTURE, 0);
                    if (!empty($matches)) {
                        $httpCode = $matches[1][0];
                        return strlen($header);
                    }
                }
                $content = trim($header);

                if (empty($content)) return strlen($header);
                list($key, $value) = explode(": ", $content);
                if (in_array(strtolower($key), ['content-length', 'transfer-encoding'])) return strlen($header);
                $headers[$key] = $value;
                return strlen($header);
            });

            curl_setopt($curl, CURLOPT_WRITEFUNCTION, function ($curl, $str) use ($response, &$socket, &$headers, &$isHeaderSended, &$httpCode) {
                if (!$isHeaderSended) {
                    $isHeaderSended = true;
                    // $response->status($httpCode);
                    if ($httpCode == 200) {
                        $socket->send("HTTP/1.1 {$httpCode} OK\r\n");
                    } else {
                        $socket->send("HTTP/1.1 {$httpCode} ERROR\r\n");
                    }

                    foreach (array_merge([
                        'Content-Type' => 'application/octet-stream',
                        'X-Accel-Buffering' => 'no',
                        'server' => 'webserver/1.0'
                    ], $headers) as $k => $v) {
                        $socket->send("{$k}: {$v}\r\n");
                    }
                    $socket->send("\r\n");
                }
                return strlen($str);
            });

            curl_exec($curl);
            curl_close($curl);

            return $socket->close();
        });

        $server->set([
            'http_compression' => false,
            'http_parse_post' => false,
            'http_parse_files' => false,
        ]);
        go(function () use ($server) {
            $server->start();
        });
        go(function () use ($server) {
            if (System::waitSignal(SIGTERM)) {
                $server->shutdown();
            }
        });
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE

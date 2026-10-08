--TEST--
swoole_curl/multi: report data ready before select
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Socket;
use Swoole\Runtime;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

Coroutine\run(function () {
    $server = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($server->bind('127.0.0.1', 0));
    Assert::true($server->listen());
    $url = 'http://127.0.0.1:' . $server->getsockname()['port'];
    $sendFirst = new Channel(1);
    $firstSent = new Channel(1);
    $sendLast = new Channel(1);

    $clientCid = Coroutine::create(function () use ($url, $sendFirst, $firstSent, $sendLast) {
        $headersReceived = false;
        $body = '';
        $handle = curl_init($url);
        $multi = curl_multi_init();
        curl_setopt_array($handle, [
            CURLOPT_PROXY => '',
            CURLOPT_TIMEOUT => 3,
            CURLOPT_HEADERFUNCTION => static function (CurlHandle $handle, string $header) use (&$headersReceived): int {
                $headersReceived = $headersReceived || $header === "\r\n";
                return strlen($header);
            },
            CURLOPT_WRITEFUNCTION => static function (CurlHandle $handle, string $chunk) use (&$body): int {
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        curl_multi_add_handle($multi, $handle);

        try {
            do {
                curl_multi_exec($multi, $running);
                if ($running && !$headersReceived) {
                    curl_multi_select($multi, 0.1);
                }
            } while ($running && !$headersReceived);

            Assert::true($headersReceived);
            Assert::true($sendFirst->push(true));
            Assert::true($firstSent->pop(2));

            try {
                $selected = curl_multi_select($multi, 0.1);
                curl_multi_exec($multi, $running);
                Assert::greaterThan($selected, 0);
                Assert::same($body, 'A');
            } finally {
                $sendLast->push(true);
            }

            do {
                curl_multi_exec($multi, $running);
                if ($running) {
                    curl_multi_select($multi, 0.1);
                }
            } while ($running);

            Assert::same($body, 'AB');
        } finally {
            curl_multi_remove_handle($multi, $handle);
            curl_multi_close($multi);
        }
    });

    $serverCid = Coroutine::create(function () use ($server, $sendFirst, $firstSent, $sendLast) {
        $client = $server->accept(2);
        Assert::isInstanceOf($client, Socket::class);

        try {
            $request = '';
            while (!str_contains($request, "\r\n\r\n")) {
                $chunk = $client->recv(2);
                Assert::string($chunk);
                Assert::notSame($chunk, '');
                $request .= $chunk;
            }

            $client->sendAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n");
            Assert::true($sendFirst->pop(2));
            Assert::same($client->sendAll('A'), 1);
            $firstSent->push(true);
            Assert::true($sendLast->pop(2));
            Assert::same($client->sendAll('B'), 1);
        } finally {
            $client->close();
        }
    });

    Assert::true(Coroutine::join([$clientCid, $serverCid]));
    $server->close();
});

echo "DONE\n";
?>
--EXPECT--
DONE

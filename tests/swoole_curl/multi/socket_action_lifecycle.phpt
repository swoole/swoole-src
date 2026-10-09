--TEST--
swoole_curl/multi: socket action handles removal, queued transfers and reuse
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;
use Swoole\Runtime;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0, false);
    $server->handle(static function (Connection $connection) {
        try {
            $request = '';
            while (!str_contains($request, "\r\n\r\n")) {
                $chunk = $connection->recv();
                if ($chunk === '' || $chunk === false) {
                    return;
                }
                $request .= $chunk;
            }
            $connection->send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
        } finally {
            $connection->close();
        }
    });
    $serverDone = new Channel(1);
    Coroutine::create(static function () use ($server, $serverDone) {
        $server->start();
        $serverDone->push(true);
    });
    $multi = curl_multi_init();
    curl_multi_setopt($multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, 1);

    for ($round = 0; $round < 3; ++$round) {
        $handles = [];
        for ($i = 0; $i < 3; ++$i) {
            $handle = curl_init("http://127.0.0.1:{$server->port}/");
            curl_setopt_array($handle, [
                CURLOPT_PROXY => '',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 3,
            ]);
            Assert::same(curl_multi_add_handle($multi, $handle), CURLM_OK);
            $handles[] = $handle;
        }

        Assert::same(curl_multi_exec($multi, $running), CURLM_OK);
        Assert::same($running, 3);
        // Remove one active/queued transfer while the other transfers still need progress.
        Assert::same(curl_multi_remove_handle($multi, $handles[0]), CURLM_OK);
        Assert::same(curl_multi_exec($multi, $running), CURLM_OK);
        Assert::same($running, 2);

        $deadline = microtime(true) + 5;
        do {
            curl_multi_select($multi, 0.1);
            Assert::same(curl_multi_exec($multi, $running), CURLM_OK);
        } while ($running && microtime(true) < $deadline);

        Assert::same($running, 0);
        $completed = 0;
        while ($message = curl_multi_info_read($multi)) {
            Assert::same($message['result'], CURLE_OK);
            ++$completed;
        }
        Assert::same($completed, 2);
        foreach (array_slice($handles, 1) as $handle) {
            Assert::same(curl_multi_getcontent($handle), 'OK');
            Assert::same(curl_multi_remove_handle($multi, $handle), CURLM_OK);
        }
        Assert::same(curl_multi_exec($multi, $running), CURLM_OK);
        Assert::same($running, 0);
        Assert::same(curl_multi_select($multi, 0), 0);
    }

    curl_multi_close($multi);
    $server->shutdown();
    Assert::true($serverDone->pop(2));
});

echo "DONE\n";
?>
--EXPECT--
DONE

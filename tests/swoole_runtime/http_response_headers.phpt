--TEST--
swoole_runtime: isolate HTTP response headers between coroutines
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Runtime;

Runtime::enableCoroutine(SWOOLE_HOOK_TCP);

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0, false);
    $server->handle('/', function (Request $request, Response $response) {
        $response->header('X-Request', ltrim($request->server['request_uri'], '/'));
        $response->end();
    });
    Coroutine::create(function () use ($server) {
        $server->start();
    });

    $url = 'http://127.0.0.1:' . $server->port;
    $request = function (string $name) use ($url): void {
        $stream = fopen("{$url}/{$name}", 'r');
        Assert::notSame($stream, false);
        fclose($stream);
    };
    $getRequestHeader = function (): ?string {
        foreach (http_get_last_response_headers() ?? [] as $header) {
            if (str_starts_with($header, 'X-Request: ')) {
                return substr($header, strlen('X-Request: '));
            }
        }
        return null;
    };

    $request('parent');
    $ready = new Channel(1);
    $release = new Channel(1);

    $first = Coroutine::create(function () use ($request, $getRequestHeader, $ready, $release) {
        $request('first');
        $ready->push(true);
        $release->pop();
        Assert::same($getRequestHeader(), 'first');
    });
    $second = Coroutine::create(function () use ($request, $ready, $release) {
        $ready->pop();
        $request('second');
        http_clear_last_response_headers();
        $release->push(true);
    });

    Assert::true(Coroutine::join([$first, $second]));
    Assert::same($getRequestHeader(), 'parent');
    $server->shutdown();
});

echo "DONE\n";
?>
--EXPECT--
DONE

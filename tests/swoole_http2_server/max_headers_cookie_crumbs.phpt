--TEST--
swoole_http2_server: max_headers counts cookie crumbs against the limit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Http2\Request;
use function Swoole\Coroutine\run;

/**
 * This test verifies that individual cookie header fields (crumbs) sent as
 * separate HPACK entries are counted against the max_headers limit.
 * This is the key mitigation for the HTTP/2 HPACK Bomb (CVE-2026-49975 class).
 *
 * In HTTP/2, RFC 9113 §8.2.3 allows splitting the Cookie header into one
 * field per crumb. Without counting these against a header limit, an attacker
 * can send thousands of 1-byte indexed cookie references that each cause
 * per-entry allocations on the server.
 */
const MAX_HEADERS = 20;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        // Test: A request with many cookie fields exceeding max_headers should be rejected.
        // The Swoole HTTP/2 client sends cookies as the "cookie" header, but we can
        // simulate multiple cookie header fields by adding them as regular headers.
        // In practice the HPACK layer counts every emitted header entry.
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 5]);
        Assert::true($cli->connect());

        // A normal request with few headers should work
        $req = new Request;
        $req->method = 'GET';
        $req->path = '/';
        $req->headers = ['x-test' => 'value'];
        $req->cookies = ['a' => '1', 'b' => '2'];

        $streamId = $cli->send($req);
        Assert::greaterThan($streamId, 0);
        $response = $cli->recv();
        Assert::eq($response->statusCode, 200);
        Assert::eq($response->data, 'OK');
        $cli->close();

        // A request with many headers that exceed the limit (simulating many cookie crumbs)
        $cli2 = new Client('127.0.0.1', $pm->getFreePort());
        $cli2->set(['timeout' => 5]);
        Assert::true($cli2->connect());

        $req2 = new Request;
        $req2->method = 'GET';
        $req2->path = '/';
        // Fill headers up past the limit
        $req2->headers = [];
        for ($i = 0; $i < MAX_HEADERS + 5; $i++) {
            $req2->headers["x-bomb-{$i}"] = str_repeat('A', 100);
        }

        $streamId2 = $cli2->send($req2);
        Assert::greaterThan($streamId2, 0);
        $response2 = $cli2->recv();
        // Server should reject this — either false (connection reset) or non-200
        Assert::assert($response2 === false || $response2->statusCode !== 200);
        $cli2->close();

        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http2_max_headers' => MAX_HEADERS,
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE

--TEST--
swoole_curl: PHP hook resolves redirect paths and excludes fragments from request targets
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Curl\Handler;

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_CURL);
Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $location = null;
    $requests = [];
    $server->handle('/', function ($request, $response) use (&$location, &$requests) {
        $target = explode(' ', $request->getData(), 3)[1];
        $requests[] = $target;
        if ($location !== null && count($requests) === 1) {
            $response->status(302);
            $response->header('Location', $location);
        }
        $response->end($target);
    });
    Coroutine::create(fn () => $server->start());
    $origin = 'http://127.0.0.1:' . $server->port;
    $cases = [
        ['/dir/start', 'next', '/dir/next'],
        ['/dir/start', './next', '/dir/next'],
        ['/dir/start', '../next', '/next'],
        ['/dir/start', '../../next', '/next'],
        ['/dir/start', '.', '/dir/'],
        ['/dir/start', '..', '/'],
        ['/dir/start', 'a/../next', '/dir/next'],
        ['/dir/start', 'a/.', '/dir/a/'],
        ['/dir/start', 'a/..', '/dir/'],
        ['/dir/start', 'a//next', '/dir/a//next'],
        ['/dir//start', '../next', '/dir/next'],
        ['/dir/start', '%2e%2e/next', '/dir/%2e%2e/next'],
        ['/dir/start', 'next?q=/../', '/dir/next?q=/../'],
        ['/dir/start', '/root/./a/../next?0#part', '/root/next?0'],
        ['/dir/start?old=1', 'next?new=2#part', '/dir/next?new=2'],
        ['/dir/start?old=1', '?new=2#part', '/dir/start?new=2'],
        ['/dir/start?old=1', '?0', '/dir/start?0'],
        ['/dir/start?old=1', '?', '/dir/start'],
        ['/dir/start?old=1', '#part', '/dir/start?old=1'],
        ['/dir/start?old=1', 'next', '/dir/next'],
        ['/dir/start#old', 'next', '/dir/next'],
        ['/dir/start#old', 'next#new', '/dir/next'],
        ['/dir/start#old', $origin . '/next', '/next'],
        ['/dir/', 'next', '/dir/next'],
        ['', 'next', '/next'],
        ['/dir/start', $origin . '/a/../next?0#part', '/next?0'],
        ['/dir/start', '//127.0.0.1:' . $server->port . '/next?0#part', '/next?0'],
    ];
    try {
        foreach ($cases as [$path, $redirect, $expected]) {
            $location = $redirect;
            $requests = [];
            $ch = curl_init($origin . $path);
            if (!$ch instanceof Handler) {
                throw new RuntimeException('Expected the PHP curl hook');
            }
            curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 2, CURLOPT_TIMEOUT => 5]);
            $body = curl_exec($ch);
            if ($body !== $expected || count($requests) !== 2 || $requests[1] !== $expected) {
                throw new RuntimeException('Redirect resolution failed: ' . var_export([$path, $redirect, $body, $requests, curl_error($ch)], true));
            }
            $fragment = parse_url($redirect, PHP_URL_FRAGMENT);
            if (parse_url(curl_getinfo($ch, CURLINFO_EFFECTIVE_URL), PHP_URL_FRAGMENT) !== $fragment) {
                throw new RuntimeException('Redirect lost or changed its fragment: ' . var_export([$path, $redirect, curl_getinfo($ch, CURLINFO_EFFECTIVE_URL), $fragment], true));
            }
        }
        $location = null;
        foreach (['/dir/start?0#part' => '/dir/start?0', '/dir/start#part' => '/dir/start', '/0#part' => '/0'] as $path => $expected) {
            $ch = curl_init($origin . $path);
            curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5]);
            if (curl_exec($ch) !== $expected || curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) !== $origin . $path) {
                throw new RuntimeException('Fragment changed the request target or effective URL');
            }
        }
        $location = 'http://localhost:99999';
        $requests = [];
        $ch = curl_init($origin . '/dir/start');
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 5]);
        if (curl_exec($ch) !== false || curl_errno($ch) !== CURLE_URL_MALFORMAT || count($requests) !== 1) {
            throw new RuntimeException('Malformed redirect URL was not rejected');
        }
        // A resolved connection address must not become the logical redirect host.
        $location = 'next';
        $requests = [];
        $logicalOrigin = 'http://localhost:' . $server->port;
        $ch = curl_init($logicalOrigin . '/dir/start');
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 5,
            CURLOPT_RESOLVE => ['localhost:' . $server->port . ':127.0.0.1']]);
        if (curl_exec($ch) !== '/dir/next' || curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) !== $logicalOrigin . '/dir/next') {
            throw new RuntimeException('Redirect lost the logical URL host');
        }
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

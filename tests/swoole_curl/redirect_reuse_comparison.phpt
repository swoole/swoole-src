--TEST--
swoole_curl: PHP and native hooks restart redirected executions at the configured URL
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;

require __DIR__ . '/../include/curl_hook_comparison.inc';
run_curl_hook_comparison(function () {
    $requests = [];
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) use (&$requests) {
        $path = $request->server['request_uri'];
        $requests[] = [$path, $request->server['request_method'], $request->getContent()];
        if ($path === '/start') {
            $response->status(302);
            $response->header('Location', '/final');
        }
        $response->end($path);
    });
    Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port;
    $ch = curl_init($url . '/start');
    curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2,
        CURLOPT_FOLLOWLOCATION => true, CURLOPT_POSTFIELDS => 'payload']);
    try {
        foreach ([1, 2] as $attempt) {
            $requests = [];
            if (curl_exec($ch) !== '/final'
                || $requests !== [['/start', 'POST', 'payload'], ['/final', 'GET', '']]
                || curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) !== $url . '/final'
                || curl_getinfo($ch, CURLINFO_REDIRECT_COUNT) !== 1) {
                throw new RuntimeException('A redirect overwrote the configured URL or method');
            }
        }
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        $requests = [];
        if (curl_exec($ch) !== '/start' || $requests !== [['/start', 'POST', 'payload']]
            || curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) !== $url . '/start') {
            throw new RuntimeException('Disabling redirects did not restore the initial URL');
        }
        curl_close($ch);
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

--TEST--
swoole_curl: PHP hook enforces protocol allowlists before sending requests
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
    $requests = 0;
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) use (&$requests) {
        $requests++;
        if (isset($request->get['to'])) {
            $response->status(302);
            $response->header('Location', $request->get['to']);
        }
        $response->end('ok');
    });
    Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $request = function ($target, $options, $expected, $count) use (&$requests) {
        $ch = curl_init($target);
        if (!$ch instanceof Handler) {
            throw new RuntimeException('Expected the PHP curl hook');
        }
        curl_setopt_array($ch, $options + [
            CURLOPT_PROXY => '',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 5,
        ]);
        $before = $requests;
        $body = curl_exec($ch);
        $errno = $expected === false ? CURLE_UNSUPPORTED_PROTOCOL : CURLE_OK;
        if ($body !== $expected || curl_errno($ch) !== $errno || $requests - $before !== $count) {
            throw new RuntimeException('Unexpected protocol result: ' . var_export([$body, curl_errno($ch), $requests - $before], true));
        }
        return $ch;
    };

    try {
        $request($url, [], 'ok', 1);
        $request($url, [CURLOPT_PROTOCOLS => CURLPROTO_HTTP], 'ok', 1);
        $request($url, [CURLOPT_PROTOCOLS => CURLPROTO_HTTPS], false, 0);
        $request($url, [CURLOPT_PROTOCOLS => 0], false, 0);
        $redirect = $url . '?to=' . urlencode($url);
        $request($redirect, [CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP], 'ok', 2);
        $request($redirect, [CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS], false, 1);
        $request($redirect, [CURLOPT_REDIR_PROTOCOLS => 0], false, 1);
        $request($redirect, [CURLOPT_REDIR_PROTOCOLS => 0, CURLOPT_FOLLOWLOCATION => false], 'ok', 1);
        $request($url . '?to=' . urlencode('ftp://127.0.0.1/file'), [], false, 1);

        // Apply changed restrictions even when the handle already has a connection.
        $ch = $request($url, [], 'ok', 1);
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        $before = $requests;
        if (curl_exec($ch) !== false || curl_errno($ch) !== CURLE_UNSUPPORTED_PROTOCOL || $requests !== $before) {
            throw new RuntimeException('Protocol restriction bypassed on handle reuse');
        }
        curl_reset($ch);
        curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true]);
        if (curl_exec($ch) !== 'ok') {
            throw new RuntimeException('Reset did not restore the protocol defaults');
        }

        $ch = curl_init();
        curl_setopt_array($ch, [CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_URL => $url]);
        $before = $requests;
        if (curl_exec($ch) !== false || curl_errno($ch) !== CURLE_UNSUPPORTED_PROTOCOL || $requests !== $before) {
            throw new RuntimeException('Protocol restriction depends on option order');
        }
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

--TEST--
swoole_curl: PHP hook enforces the redirect limit and PHP's default of 20
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
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $server->handle('/', function ($request, $response) use (&$requests, $url) {
        $requests++;
        $remaining = (int) ($request->get['n'] ?? 0);
        if ($remaining > 0) {
            $response->status(302);
            $response->header('Location', $url . '?n=' . ($remaining - 1));
        }
        $response->end('ok');
    });
    Coroutine::create(fn () => $server->start());

    $options = [
        CURLOPT_PROXY => '',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 5,
    ];
    $request = function ($remaining, $extra, $redirects, $failed, $limit = null) use ($url, $options, &$requests) {
        $ch = curl_init($url . '?n=' . $remaining);
        if (!$ch instanceof Handler) {
            throw new RuntimeException('Expected the PHP curl hook');
        }
        curl_setopt_array($ch, $extra + $options);
        $before = $requests;
        $body = curl_exec($ch);
        $info = curl_getinfo($ch);
        $errno = $failed ? CURLE_TOO_MANY_REDIRECTS : CURLE_OK;
        if ($body !== ($failed ? false : 'ok') || curl_errno($ch) !== $errno ||
            $info['redirect_count'] !== $redirects || $requests - $before !== $redirects + 1) {
            throw new RuntimeException('Unexpected redirect result: ' . var_export([$body, curl_errno($ch), $info['redirect_count'], $requests - $before], true));
        }
        if ($failed && ($info['http_code'] !== 302 ||
            $info['redirect_url'] !== $url . '?n=' . ($remaining - $redirects - 1) ||
            curl_error($ch) !== "Maximum ({$limit}) redirects followed")) {
            throw new RuntimeException('Redirect failure lost response information');
        }
        return $ch;
    };

    try {
        // The limit counts followed redirects, not requests; reaching a final 200 at the limit succeeds.
        $request(0, [CURLOPT_MAXREDIRS => 0], 0, false);
        $request(1, [CURLOPT_MAXREDIRS => 0], 0, true, 0);
        $request(1, [CURLOPT_MAXREDIRS => 1], 1, false);
        $request(2, [CURLOPT_MAXREDIRS => 1], 1, true, 1);
        $request(2, [CURLOPT_MAXREDIRS => 2], 2, false);
        $request(3, [CURLOPT_MAXREDIRS => 2], 2, true, 2);
        $request(20, [], 20, false);
        $request(21, [], 20, true, 20);
        $request(25, [CURLOPT_MAXREDIRS => -1], 25, false);
        $request(2, [CURLOPT_MAXREDIRS => 0, CURLOPT_FOLLOWLOCATION => false], 0, false);

        $ch = $request(0, [CURLOPT_MAXREDIRS => -1], 0, false);
        curl_reset($ch);
        curl_setopt_array($ch, $options + [CURLOPT_URL => $url . '?n=21']);
        $before = $requests;
        if (curl_exec($ch) !== false || curl_errno($ch) !== CURLE_TOO_MANY_REDIRECTS ||
            curl_getinfo($ch, CURLINFO_REDIRECT_COUNT) !== 20 || $requests - $before !== 21) {
            throw new RuntimeException('Reset did not restore the default redirect limit');
        }

        // Invalid values must not replace an existing limit.
        $ch = curl_init($url . '?n=1');
        curl_setopt_array($ch, $options + [CURLOPT_MAXREDIRS => 0]);
        if (curl_setopt($ch, CURLOPT_MAXREDIRS, -2) !== false || curl_errno($ch) !== CURLE_BAD_FUNCTION_ARGUMENT ||
            curl_exec($ch) !== false || curl_errno($ch) !== CURLE_TOO_MANY_REDIRECTS) {
            throw new RuntimeException('Invalid MAXREDIRS was accepted');
        }

        $ch = curl_init($url . '?n=1');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => false, CURLOPT_MAXREDIRS => 0] + $options);
        ob_start();
        $body = curl_exec($ch);
        $output = ob_get_clean();
        if ($body !== false || $output !== '' || curl_errno($ch) !== CURLE_TOO_MANY_REDIRECTS) {
            throw new RuntimeException('Redirect failure returned or printed a successful body');
        }
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

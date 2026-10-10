--TEST--
swoole_curl: PHP hook shares one total timeout across redirects and resets it for each execution
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
    $servers = [new Server('127.0.0.1', 0), new Server('127.0.0.1', 0)];
    $origins = array_map(fn ($server) => 'http://127.0.0.1:' . $server->port, $servers);
    foreach ($servers as $index => $server) {
        $server->handle('/', function ($request, $response) use ($origins, $index) {
            $hops = (int) ($request->get['hops'] ?? 0);
            $delay = (int) ($request->get['delay'] ?? 0);
            $cross = (int) ($request->get['cross'] ?? 0);
            if ($delay > 0) {
                Coroutine::sleep($delay / 1000);
            }
            if ($hops > 0) {
                $response->status(302);
                $origin = $origins[$cross ? 1 - $index : $index];
                $response->header('Location', $origin . '/?hops=' . ($hops - 1) . '&delay=' . $delay . '&cross=' . $cross);
            }
            $response->end($hops > 0 ? 'redirect' : 'ok');
        });
        Coroutine::create(fn () => $server->start());
    }
    $request = function ($hops, $delay, $cross, $options) use ($origins) {
        $ch = curl_init($origins[0] . '/?hops=' . $hops . '&delay=' . $delay . '&cross=' . (int) $cross);
        if (!$ch instanceof Handler) {
            throw new RuntimeException('Expected the PHP curl hook');
        }
        curl_setopt_array($ch, $options + [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 10, CURLOPT_CONNECTTIMEOUT => 5]);
        return $ch;
    };
    $expectTimeout = function ($ch, $limit) {
        $start = hrtime(true);
        $body = curl_exec($ch);
        $elapsed = (hrtime(true) - $start) / 1e9;
        $info = curl_getinfo($ch);
        if ($body !== false || curl_errno($ch) !== CURLE_OPERATION_TIMEDOUT || curl_error($ch) === ''
            || $elapsed < $limit * 0.7 || $elapsed > $limit + 0.6
            || abs($info['total_time'] - $elapsed) > 0.1) {
            throw new RuntimeException('Total timeout was not enforced: ' . var_export([$body, curl_errno($ch), $elapsed, $info], true));
        }
    };
    try {
        foreach ([false, true] as $cross) {
            // Each hop is below 200 ms, but the complete chain takes 480 ms.
            $ch = $request(5, 80, $cross, [CURLOPT_TIMEOUT_MS => 200]);
            $expectTimeout($ch, 0.2);
            if (curl_getinfo($ch, CURLINFO_REDIRECT_COUNT) < 1 || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 302) {
                throw new RuntimeException('The transfer did not reach a redirect');
            }
            // A new execution gets a fresh budget and clears the previous timeout error.
            curl_setopt($ch, CURLOPT_URL, $origins[0] . '/?delay=50');
            if (curl_exec($ch) !== 'ok' || curl_errno($ch) !== CURLE_OK) {
                throw new RuntimeException('Timeout poisoned the next execution');
            }
        }
        $expectTimeout($request(3, 350, false, [CURLOPT_TIMEOUT => 1]), 1.0);
        $expectTimeout($request(0, 350, false, [CURLOPT_TIMEOUT_MS => 100]), 0.1);

        // Reusing a successful handle must not reuse a reduced per-hop timeout or deadline.
        $ch = $request(2, 80, false, [CURLOPT_TIMEOUT_MS => 500]);
        for ($i = 0; $i < 2; $i++) {
            curl_setopt($ch, CURLOPT_URL, $origins[0] . '/?hops=2&delay=80');
            if (curl_exec($ch) !== 'ok' || curl_errno($ch) !== CURLE_OK) {
                throw new RuntimeException('The configured timeout was changed');
            }
        }

        // A completed transfer must remove its deadline timer before a slower subsequent transfer.
        $ch = $request(0, 0, false, [CURLOPT_TIMEOUT_MS => 100]);
        if (curl_exec($ch) !== 'ok') {
            throw new RuntimeException('Initial fast transfer failed');
        }
        curl_setopt_array($ch, [CURLOPT_URL => $origins[0] . '/?delay=250', CURLOPT_TIMEOUT_MS => 1000]);
        if (curl_exec($ch) !== 'ok') {
            throw new RuntimeException('An old deadline interrupted a later transfer');
        }

        $ch = $request(5, 80, false, [CURLOPT_TIMEOUT_MS => 200, CURLOPT_FOLLOWLOCATION => false]);
        if (curl_exec($ch) !== 'redirect' || curl_getinfo($ch, CURLINFO_REDIRECT_COUNT) !== 0) {
            throw new RuntimeException('FOLLOWLOCATION=false unexpectedly followed a redirect');
        }

        // Explicit zero and the default mean unlimited, even with a shorter HTTP client read default.
        Coroutine::set(['socket_read_timeout' => 0.03]);
        foreach ([[], [CURLOPT_TIMEOUT => 0], [CURLOPT_TIMEOUT_MS => 0]] as $options) {
            $ch = $request(2, 60, true, $options);
            if (curl_exec($ch) !== 'ok' || curl_errno($ch) !== CURLE_OK) {
                throw new RuntimeException('An unlimited transfer inherited the HTTP client timeout');
            }
        }
    } finally {
        foreach ($servers as $server) {
            $server->shutdown();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

--TEST--
swoole_curl: PHP hook aborts on short write callbacks with CURLE_WRITE_ERROR
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
    $chunks = [str_repeat('a', 32), str_repeat('b', 32), str_repeat('c', 32)];
    $server->handle('/', function ($request, $response) use ($chunks) {
        $response->header('Content-Type', 'text/plain');
        foreach ($chunks as $chunk) {
            if (!$response->write($chunk)) {
                return;
            }
            Coroutine::sleep(0.02);
        }
        $response->end();
    });
    Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $options = [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2];
    try {
        $callbacks = [
            fn ($data) => 0,
            fn ($data) => false,
            fn ($data) => null,
            fn ($data) => -1,
            fn ($data) => strlen($data) - 1,
            fn ($data) => strlen($data) + 1,
        ];
        if (defined('CURL_WRITEFUNC_ERROR')) {
            $callbacks[] = fn ($data) => CURL_WRITEFUNC_ERROR;
        }
        foreach ($callbacks as $callback) {
            foreach ([1, 2] as $abortAt) {
                $calls = 0;
                $body = '';
                $ch = curl_init($url);
                if (!$ch instanceof Handler) {
                    throw new RuntimeException('Expected the PHP curl hook');
                }
                curl_setopt_array($ch, $options + [CURLOPT_WRITEFUNCTION => function ($ch, $data) use ($callback, $abortAt, &$calls, &$body) {
                    $calls++;
                    $body .= $data;
                    return $calls === $abortAt ? $callback($data) : strlen($data);
                }]);
                if (curl_exec($ch) !== false || curl_errno($ch) !== CURLE_WRITE_ERROR || curl_error($ch) === ''
                    || $calls !== $abortAt || $body !== implode('', array_slice($chunks, 0, $abortAt))
                    || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 200
                    || curl_getinfo($ch, CURLINFO_CONTENT_TYPE) !== 'text/plain') {
                    throw new RuntimeException('Short write did not abort correctly: ' . var_export([$calls, curl_errno($ch), curl_getinfo($ch)], true));
                }
                $received = '';
                curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $data) use (&$received) {
                    $received .= $data;
                    return strlen($data);
                });
                if (curl_exec($ch) === false || curl_errno($ch) !== CURLE_OK || $received !== implode('', $chunks)) {
                    throw new RuntimeException('Write error poisoned the next execution');
                }
                curl_close($ch);
            }
        }
        // PHP's native cURL converts the callback result to an integer byte count.
        foreach ([fn ($data) => strlen($data), fn ($data) => (string) strlen($data), fn ($data) => (float) strlen($data)] as $callback) {
            $body = '';
            $ch = curl_init($url);
            curl_setopt_array($ch, $options + [CURLOPT_WRITEFUNCTION => function ($ch, $data) use ($callback, &$body) {
                $body .= $data;
                return $callback($data);
            }]);
            if (curl_exec($ch) === false || curl_errno($ch) !== CURLE_OK || $body !== implode('', $chunks)) {
                throw new RuntimeException('A full write was rejected');
            }
            curl_close($ch);
        }
        // Aborting must not echo the remaining response when RETURNTRANSFER is disabled.
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => false,
            CURLOPT_WRITEFUNCTION => fn ($ch, $data) => 0] + $options);
        ob_start();
        $result = curl_exec($ch);
        $output = ob_get_clean();
        if ($result !== false || $output !== '' || curl_errno($ch) !== CURLE_WRITE_ERROR) {
            throw new RuntimeException('Aborted transfer returned or printed success');
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

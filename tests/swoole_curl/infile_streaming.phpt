--TEST--
swoole_curl: stream known-length file uploads with bounded memory, redirect replay and address failover
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';
require __DIR__ . '/../include/curl_hook_comparison.inc';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Curl\Handler;

Assert::setThrowException(true);
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_CURL | SWOOLE_HOOK_FILE);
Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        $file = tmpfile();
        $block = str_repeat("binary\0\xff", 8192);
        $length = strlen($block) * 256;
        fwrite($file, 'prefix');
        $hash = hash_init('sha256');
        for ($i = 0; $i < 256; $i++) {
            fwrite($file, $block);
            hash_update($hash, $block);
        }
        fwrite($file, 'unused-tail');
        $expected = hash_final($hash);
        $listener = http_client_body_listener($ssl);
        Coroutine::create(function () use ($listener, $ssl, $length, $expected) {
            for ($i = 0; $i < 2; $i++) {
                $peer = $listener->accept(5);
                Assert::notSame($peer, false);
                if ($ssl) {
                    Assert::true($peer->sslHandshake());
                }
                $buffer = '';
                $request = http_client_body_headers($peer, $buffer);
                Assert::same($request['length'], $length);
                Assert::same(http_client_body_digest($peer, $buffer, $length), $expected);
                http_client_body_reply($peer, $expected, 200, true);
                $peer->close();
            }
        });
        $url = ($ssl ? 'https' : 'http') . '://127.0.0.1:' . $listener->getsockname()['port'] . '/';
        $curl = curl_init($url);
        Assert::isInstanceOf($curl, Handler::class);
        curl_setopt_array($curl, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5,
            CURLOPT_UPLOAD => true, CURLOPT_INFILE => $file, CURLOPT_INFILESIZE => $length,
            CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_HTTPHEADER => ['Expect:']]);
        memory_reset_peak_usage();
        $baseline = memory_get_usage();
        for ($i = 0; $i < 2; $i++) {
            fseek($file, strlen('prefix'));
            Assert::same(curl_exec($curl), $expected);
            Assert::same(curl_errno($curl), CURLE_OK);
            Assert::same(ftell($file), strlen('prefix') + $length);
            Assert::same((int) curl_getinfo($curl, CURLINFO_SIZE_UPLOAD), $length);
        }
        Assert::lessThan(memory_get_peak_usage() - $baseline, 4 * 1024 * 1024);
        curl_close($curl);
        Assert::true(is_resource($file));
        fclose($file);
        $listener->close();
    }
});

run_curl_hook_comparison(function ($hook) {
    $rewindError = defined('CURLE_SEND_FAIL_REWIND') ? constant('CURLE_SEND_FAIL_REWIND') : 65;
    foreach ([0, 307, 308, 303] as $redirect) {
        $payload = str_repeat("file\0content", 1024);
        $length = 4097;
        $expected = substr($payload, 0, $length);
        $server = new Server('127.0.0.1', 0);
        $server->set(['http_compression' => false]);
        $requests = 0;
        $server->handle('/', function ($request, $response) use ($redirect, $expected, &$requests) {
            $requests++;
            $isGet = $redirect === 303 && $request->server['request_uri'] === '/next';
            Assert::same($request->server['request_method'], $isGet ? 'GET' : 'PUT');
            Assert::same($request->getContent(), $isGet ? '' : $expected);
            if ($redirect && $request->server['request_uri'] === '/') {
                $response->status($redirect);
                $response->header('Location', '/next');
            }
            $response->header('Connection', 'close');
            $response->end('done');
        });
        Coroutine::create(fn () => $server->start());
        $file = tmpfile();
        fwrite($file, 'pre' . $payload . 'unused-tail');
        fseek($file, 3);
        $url = 'http://upload.test:' . $server->port . '/';
        $curl = curl_init($url);
        try {
            curl_setopt_array($curl, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5,
                CURLOPT_FOLLOWLOCATION => true, CURLOPT_UPLOAD => true, CURLOPT_INFILE => $file,
                CURLOPT_INFILESIZE => $length, CURLOPT_HTTPHEADER => ['Expect:'],
                CURLOPT_RESOLVE => ['upload.test:' . $server->port . ':127.0.0.2,127.0.0.1']]);
            $result = curl_exec($curl);
            // Some native PHP/libcurl bindings cannot rewind infile streams for a redirect.
            // The PHP hook must replay them successfully; native rewind failures are explicit.
            if ($hook === SWOOLE_HOOK_NATIVE_CURL && $redirect && $result === false
                && curl_errno($curl) === $rewindError) {
                Assert::same($requests, 1);
                continue;
            }
            Assert::same($result, 'done', 'redirect:' . $redirect . ' hook:' . $hook . ' error:' . curl_error($curl));
            Assert::same(curl_errno($curl), CURLE_OK);
            Assert::same($requests, $redirect ? 2 : 1);
            // Native cURL does not necessarily advance PHP's logical stream position.
            if ($hook === SWOOLE_HOOK_CURL) {
                Assert::same(ftell($file), 3 + $length);
            }
        } finally {
            curl_close($curl);
            fclose($file);
            $server->shutdown();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

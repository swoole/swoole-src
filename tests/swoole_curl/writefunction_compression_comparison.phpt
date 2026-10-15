--TEST--
swoole_curl: compressed WRITEFUNCTION delivery and recovery match native curl
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
skip_if_extension_not_exist('zlib');
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/curl_hook_comparison.inc';
require __DIR__ . '/../include/http_compression_fixture.inc';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;

Assert::setThrowException(true);
run_curl_hook_comparison(function () {
    [$expected, $encoded] = http_compression_fixture();
    if (!defined('CURL_VERSION_BROTLI') || !(curl_version()['features'] & CURL_VERSION_BROTLI)) {
        unset($encoded['br']);
    }
    $server = new Server('127.0.0.1', 0);
    $server->set(['http_compression' => false]);
    $server->handle('/', function ($request, $response) use ($encoded) {
        $encoding = $request->get['encoding'];
        $wire = $encoded[$encoding];
        $response->header('Content-Type', 'application/json');
        $response->header('Content-Encoding', $encoding);
        if ($request->get['framing'] === 'length') {
            $response->end($wire);
            return;
        }
        foreach (str_split($wire, 5) as $part) {
            if (!$response->write($part)) {
                return;
            }
        }
        $response->end();
    });
    $chunks = [str_repeat('A', 1024), str_repeat('B', 1024), str_repeat('C', 1024)];
    $server->handle('/stream', function ($request, $response) use ($chunks) {
        $encoding = $request->get['encoding'];
        $context = deflate_init($encoding === 'gzip' ? ZLIB_ENCODING_GZIP : ZLIB_ENCODING_DEFLATE);
        $response->header('Content-Encoding', $encoding);
        foreach ($chunks as $chunk) {
            if (!$response->write(deflate_add($context, $chunk, ZLIB_SYNC_FLUSH))) {
                return;
            }
            Coroutine::sleep(0.02);
        }
        $response->write(deflate_add($context, '', ZLIB_FINISH));
        $response->end();
    });
    $cid = Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port;
    $options = [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_ENCODING => '', CURLOPT_TIMEOUT => 3];
    try {
        foreach (array_keys($encoded) as $encoding) {
            foreach (['length', 'chunked'] as $framing) {
                foreach ([false, true] as $callback) {
                    $received = '';
                    $ch = curl_init($url . '/?encoding=' . $encoding . '&framing=' . $framing);
                    curl_setopt_array($ch, $options);
                    if ($callback) {
                        curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $chunk) use (&$received) {
                            $received .= $chunk;
                            return strlen($chunk);
                        });
                    }
                    $result = curl_exec($ch);
                    Assert::same($result, $callback ? true : $expected);
                    Assert::same($callback ? $received : $result, $expected);
                    Assert::same(curl_errno($ch), CURLE_OK);
                    Assert::same(curl_getinfo($ch, CURLINFO_RESPONSE_CODE), 200);
                    curl_close($ch);
                }
            }
        }
        // Abort on decoded data without assuming a callback preserves HTTP chunk boundaries.
        foreach (['gzip', 'deflate'] as $encoding) {
            $ch = curl_init($url . '/stream?encoding=' . $encoding);
            curl_setopt_array($ch, $options);
            $received = '';
            curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $chunk) use (&$received) {
                $received .= $chunk;
                return 0;
            });
            Assert::false(curl_exec($ch));
            Assert::same(curl_errno($ch), CURLE_WRITE_ERROR);
            Assert::greaterThan(strlen($received), 0);
            Assert::lessThan(strlen($received), strlen(implode('', $chunks)));
            Assert::startsWith(implode('', $chunks), $received);

            $received = '';
            curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $chunk) use (&$received) {
                $received .= $chunk;
                return strlen($chunk);
            });
            Assert::true(curl_exec($ch));
            Assert::same(curl_errno($ch), CURLE_OK);
            Assert::same($received, implode('', $chunks));
            curl_close($ch);
        }
    } finally {
        $server->shutdown();
        Coroutine::join([$cid]);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

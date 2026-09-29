--TEST--
swoole_curl: hooked file streams stay on the PHP thread
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
?>
--FILE--
<?php
use Swoole\Runtime;
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use function Swoole\Coroutine\run;

$inputPath = __DIR__ . '/file_hook_stream.input';
$outputPath = __DIR__ . '/file_hook_stream.output';
$headerPath = __DIR__ . '/file_hook_stream.headers';
$body = random_bytes(32 * 1024);
file_put_contents($inputPath, $body);

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL | SWOOLE_HOOK_FILE);
run(function () use ($body, $inputPath, $outputPath, $headerPath) {
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) use ($body) {
        $response->end($request->getContent() === $body ? 'ok' : 'bad');
    });
    Coroutine::create(function () use ($server) {
        $server->start();
    });

    try {
        $input = fopen($inputPath, 'rb');
        $output = fopen($outputPath, 'wb');
        $headers = fopen($headerPath, 'wb');
        $ch = curl_init('http://127.0.0.1:' . $server->port);
        curl_setopt_array($ch, [
            CURLOPT_UPLOAD => true,
            CURLOPT_INFILE => $input,
            CURLOPT_INFILESIZE => filesize($inputPath),
            CURLOPT_FILE => $output,
            CURLOPT_WRITEHEADER => $headers,
            CURLOPT_HTTPHEADER => ['Expect:'],
        ]);

        if (curl_exec($ch) !== true || curl_getinfo($ch, CURLINFO_HTTP_CODE) !== 200) {
            throw new RuntimeException(curl_error($ch));
        }
        unset($ch);
        fclose($input);
        fclose($output);
        fclose($headers);

        if (file_get_contents($outputPath) !== 'ok' ||
            !str_starts_with(file_get_contents($headerPath), 'HTTP/1.1 200')) {
            throw new RuntimeException('curl file streams returned unexpected content');
        }
    } finally {
        $server->shutdown();
    }
});
echo "Done\n";
?>
--EXPECT--
Done
--CLEAN--
<?php
@unlink(__DIR__ . '/file_hook_stream.input');
@unlink(__DIR__ . '/file_hook_stream.output');
@unlink(__DIR__ . '/file_hook_stream.headers');
?>

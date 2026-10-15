--TEST--
swoole_curl: PHP hook preserves multipart files across handle reuse and redirects
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
    $files = [tempnam(sys_get_temp_dir(), 'swoole-curl-'), tempnam(sys_get_temp_dir(), 'swoole-curl-')];
    $contents = ["first\0file\r\n", '0'];
    foreach ($files as $i => $file) {
        file_put_contents($file, $contents[$i]);
    }
    $requests = [];
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) use (&$requests) {
        $uploads = [];
        foreach ($request->files ?? [] as $key => $file) {
            $uploads[$key] = [$file['name'], $file['type'], $file['error'], base64_encode(file_get_contents($file['tmp_name']))];
        }
        ksort($uploads);
        $data = [$request->server['request_method'], $request->post ?? [], $uploads];
        $requests[] = $data;
        if (isset($request->get['redirect'])) {
            $response->status((int) $request->get['redirect']);
            $response->header('Location', '/');
        }
        $response->end(json_encode($data));
    });
    Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $fields = ['text' => 'value', 'zero' => '0',
        'first' => new CURLFile($files[0], 'application/octet-stream', 'first.bin'),
        'second' => new CURLFile($files[1], 'text/plain', 'second.txt')];
    $expected = ['POST', ['text' => 'value', 'zero' => '0'], [
        'first' => ['first.bin', 'application/octet-stream', 0, base64_encode($contents[0])],
        'second' => ['second.txt', 'text/plain', 0, base64_encode($contents[1])],
    ]];
    $ch = curl_init($url);
    if (!$ch instanceof Handler) {
        throw new RuntimeException('Expected the PHP curl hook');
    }
    curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3,
        CURLOPT_FOLLOWLOCATION => true, CURLOPT_POSTFIELDS => $fields]);
    try {
        // Do not set POSTFIELDS again: every execution must retain the original CURLFile entries.
        foreach (['', '', '?redirect=307', '?redirect=308', ''] as $suffix) {
            curl_setopt($ch, CURLOPT_URL, $url . $suffix);
            $requests = [];
            $result = curl_exec($ch);
            $expectedRequests = array_fill(0, $suffix === '' ? 1 : 2, $expected);
            if ($result === false || json_decode($result, true) !== $expected || $requests !== $expectedRequests) {
                throw new RuntimeException('Multipart files were not resent: ' . var_export([$requests, curl_error($ch)], true));
            }
        }
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        if (json_decode(curl_exec($ch), true) !== ['GET', [], []]) {
            throw new RuntimeException('GET retained multipart upload data');
        }
        curl_close($ch);
    } finally {
        $server->shutdown();
        foreach ($files as $file) {
            unlink($file);
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

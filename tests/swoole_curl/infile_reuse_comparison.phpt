--TEST--
swoole_curl: PHP and native hooks preserve upload streams and lengths across executions
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
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) {
        if (isset($request->get['redirect'])) {
            $response->status((int) $request->get['redirect']);
            $response->header('Location', '/');
        }
        $response->end($request->getContent());
    });
    Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $file = tmpfile();
    $body = "file\0data\r\n";
    fwrite($file, $body);
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2,
        CURLOPT_FOLLOWLOCATION => true, CURLOPT_UPLOAD => true, CURLOPT_INFILE => $file, CURLOPT_INFILESIZE => strlen($body)]);
    try {
        foreach (['', '', ''] as $suffix) {
            rewind($file);
            curl_setopt($ch, CURLOPT_URL, $url . $suffix);
            if (curl_exec($ch) !== $body || curl_errno($ch) !== CURLE_OK) {
                throw new RuntimeException('An upload stream or its length was lost: ' . curl_error($ch));
            }
        }
        curl_close($ch);
    } finally {
        fclose($file);
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

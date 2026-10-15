--TEST--
swoole_curl: PHP hook switches body modes and sends zero and empty POST strings
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
    $server->handle('/', function ($request, $response) {
        $response->end(json_encode([
            $request->server['request_method'],
            $request->getContent(),
            $request->header['content-type'] ?? '',
            $request->header['content-length'] ?? '',
        ]));
    });
    Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $ch = curl_init($url);
    if (!$ch instanceof Handler) {
        throw new RuntimeException('Expected the PHP curl hook');
    }
    curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5]);
    $expect = function ($method, $body, $contentType = '') use ($ch) {
        $response = curl_exec($ch);
        $actual = $response === false ? false : json_decode($response, true);
        $expected = [$method, $body, $contentType, $contentType === '' ? '' : (string) strlen($body)];
        if ($actual !== $expected) {
            throw new RuntimeException('Unexpected body state: ' . var_export([$actual, $expected], true));
        }
    };
    $form = 'application/x-www-form-urlencoded';

    try {
        curl_setopt($ch, CURLOPT_POSTFIELDS, 'payload');
        $expect('POST', 'payload', $form);
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        $expect('GET', '');
        curl_setopt($ch, CURLOPT_POST, true);
        $expect('POST', 'payload', $form);
        curl_setopt($ch, CURLOPT_HTTPGET, false);
        $expect('POST', 'payload', $form);

        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, 'new');
        $expect('POST', 'new', $form);
        foreach (['0', '', '00', '0'] as $body) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            $expect('POST', $body, $form);
        }

        // CUSTOMREQUEST changes the wire method, independently of whether a body is sent.
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
        curl_setopt($ch, CURLOPT_POSTFIELDS, 'payload');
        $expect('PATCH', 'payload', $form);
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        $expect('PATCH', '');
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, null);
        $expect('GET', '');

        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        $expect('GET', '');

        $input = fopen('php://temp', 'w+');
        fwrite($input, 'upload');
        rewind($input);
        curl_setopt_array($ch, [CURLOPT_UPLOAD => true, CURLOPT_INFILE => $input, CURLOPT_INFILESIZE => 6]);
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        $expect('GET', '');
        if (ftell($input) !== 0) {
            throw new RuntimeException('HTTPGET consumed the configured upload stream');
        }
        curl_close($ch);
        fclose($input);
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

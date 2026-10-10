--TEST--
swoole_curl: PHP hook replaces custom headers and preserves option-generated headers
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
        $headers = $request->header;
        $headers['cookie'] = http_build_query($request->cookie ?? [], '', '; ');
        $response->end(json_encode($headers));
    });
    Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $ch = curl_init($url);
    if (!$ch instanceof Handler) {
        throw new RuntimeException('Expected the PHP curl hook');
    }
    curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5]);
    $expect = function ($expected, $absent = []) use ($ch) {
        $response = curl_exec($ch);
        if ($response === false) {
            throw new RuntimeException(curl_error($ch));
        }
        $headers = json_decode($response, true);
        foreach ($expected as $name => $value) {
            if (($headers[$name] ?? null) !== $value) {
                throw new RuntimeException('Unexpected header ' . $name . ': ' . var_export($headers, true));
            }
        }
        foreach ($absent as $name) {
            if (isset($headers[$name])) {
                throw new RuntimeException('Old header was retained: ' . $name);
            }
        }
        return $headers;
    };

    try {
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-Old: old']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-New: new']);
        $expect(['x-new' => 'new'], ['x-old']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-Last: last']);
        $expect(['x-last' => 'last'], ['x-old', 'x-new']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, []);
        $expect([], ['x-old', 'x-new', 'x-last']);

        curl_setopt_array($ch, [
            CURLOPT_USERPWD => 'user:secret',
            CURLOPT_USERAGENT => 'option-agent',
            CURLOPT_REFERER => 'http://example.test/',
            CURLOPT_COOKIE => 'option=secret',
        ]);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'aUtHoRiZaTiOn: Bearer custom',
            'uSeR-aGeNt: custom-agent',
            'Referer: http://custom.test/',
            'Cookie: custom=secret',
        ]);
        curl_setopt($ch, CURLOPT_USERAGENT, 'updated-agent');
        $expect(['authorization' => 'Bearer custom', 'user-agent' => 'custom-agent', 'referer' => 'http://custom.test/', 'cookie' => 'custom=secret']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-New: new']);
        $generated = [
            'authorization' => 'Basic ' . base64_encode('user:secret'),
            'user-agent' => 'updated-agent',
            'referer' => 'http://example.test/',
            'cookie' => 'option=secret',
        ];
        $expect($generated + ['x-new' => 'new']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization:']);
        $expect([], ['authorization', 'x-new']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, []);
        $expect($generated);

        curl_setopt($ch, CURLOPT_POSTFIELDS, 'payload');
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/custom']);
        $expect(['content-type' => 'application/custom']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, []);
        $expect(['content-type' => 'application/x-www-form-urlencoded']);

        curl_setopt_array($ch, [
            CURLOPT_URL => 'http://localhost:' . $server->port . '/',
            CURLOPT_RESOLVE => ['localhost:' . $server->port . ':127.0.0.1'],
            CURLOPT_HTTPHEADER => ['Host: custom.test'],
        ]);
        $expect(['host' => 'custom.test']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, []);
        $headers = $expect([]);
        if (parse_url('http://' . $headers['host'], PHP_URL_HOST) !== 'localhost') {
            throw new RuntimeException('Replacing headers lost the URL host after CURLOPT_RESOLVE');
        }
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

--TEST--
swoole_curl: PHP and native hooks verify certificate chains and names independently before sending requests
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
skip_if_no_ssl();
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;

require __DIR__ . '/../include/curl_hook_comparison.inc';
run_curl_hook_comparison(function () {
    Swoole\Coroutine::set(['log_level' => SWOOLE_LOG_NONE]);
    $server = new Server('127.0.0.1', 0, true);
    $server->set([
        'ssl_cert_file' => __DIR__ . '/../include/ssl_certs/curl-server.crt',
        'ssl_key_file' => __DIR__ . '/../include/ssl_certs/server.key',
    ]);
    $requests = 0;
    $server->handle('/', function ($request, $response) use (&$requests) {
        $requests++;
        $response->end('TLS');
    });
    Coroutine::create(fn () => $server->start());
    $ca = __DIR__ . '/../include/ssl_certs/ca.crt';
    $check = function ($host, $options, $success) use ($server, &$requests) {
        $ch = curl_init('https://' . $host . ':' . $server->port . '/');
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2,
            CURLOPT_RESOLVE => [$host . ':' . $server->port . ':127.0.0.1']]);
        curl_setopt_array($ch, $options);
        $before = $requests;
        $result = @curl_exec($ch);
        if ($result !== ($success ? 'TLS' : false)
            || curl_errno($ch) !== ($success ? CURLE_OK : CURLE_SSL_CACERT)
            || $requests !== $before + (int) $success) {
            throw new RuntimeException('Unexpected TLS verification: ' . var_export([$host, $options, $result, curl_errno($ch), curl_error($ch)], true));
        }
        curl_close($ch);
    };
    try {
        $check('localhost', [], false);
        $check('localhost', [CURLOPT_SSL_VERIFYPEER => false], true);
        $check('localhost', [CURLOPT_CAINFO => $ca], true);
        $check('127.0.0.1', [CURLOPT_CAINFO => $ca], true);
        $check('wrong.test', [CURLOPT_CAINFO => $ca], false);
        $check('wrong.test', [CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 2], false);
        $check('wrong.test', [CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0], true);
        $check('wrong.test', [CURLOPT_CAINFO => $ca, CURLOPT_SSL_VERIFYHOST => 0], true);
        $check('wrong.test', [CURLOPT_SSL_VERIFYHOST => 0], false);

        $ch = curl_init('https://localhost:' . $server->port . '/');
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2,
            CURLOPT_RESOLVE => ['localhost:' . $server->port . ':127.0.0.1'], CURLOPT_SSL_VERIFYPEER => false]);
        if (curl_exec($ch) !== 'TLS') {
            throw new RuntimeException('Initial unverified request failed');
        }
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        if (@curl_exec($ch) !== false || curl_errno($ch) !== CURLE_SSL_CACERT) {
            throw new RuntimeException('Enabling verification reused an unverified connection');
        }
        curl_setopt($ch, CURLOPT_CAINFO, $ca);
        if (curl_exec($ch) !== 'TLS' || curl_errno($ch) !== CURLE_OK || curl_error($ch) !== '') {
            throw new RuntimeException('A TLS failure poisoned handle reuse');
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

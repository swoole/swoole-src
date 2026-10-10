--TEST--
swoole_curl: PHP and native hooks expose real connection statistics and clear failed transfer information
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Socket;

require __DIR__ . '/../include/curl_hook_comparison.inc';
run_curl_hook_comparison(function ($mode) {
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) {
        $response->header('Content-Type', 'text/plain');
        $response->header('Connection', 'close');
        Coroutine::sleep(0.01);
        $response->end('BODY');
    });
    Coroutine::create(fn () => $server->start());
    $reserved = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (!$reserved->bind('127.0.0.1', 0)) {
        throw new RuntimeException('Cannot reserve a refused port');
    }
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2,
        CURLOPT_POSTFIELDS => 'payload', CURLINFO_HEADER_OUT => true, CURLOPT_PRIVATE => 'keep-me']);
    try {
        if (curl_exec($ch) !== 'BODY') {
            throw new RuntimeException('Initial request failed');
        }
        $info = curl_getinfo($ch);
        foreach ([
            CURLINFO_PRIMARY_IP => '127.0.0.1', CURLINFO_PRIMARY_PORT => $server->port,
            CURLINFO_LOCAL_IP => '127.0.0.1', CURLINFO_HTTP_CODE => 200, CURLINFO_CONTENT_TYPE => 'text/plain',
            CURLINFO_SIZE_DOWNLOAD => 4.0, CURLINFO_SIZE_UPLOAD => 7.0,
            CURLINFO_CONTENT_LENGTH_DOWNLOAD => 4.0, CURLINFO_CONTENT_LENGTH_UPLOAD => 7.0,
            CURLINFO_HTTP_VERSION => CURL_HTTP_VERSION_1_1, CURLINFO_SCHEME => 'HTTP', CURLINFO_PROTOCOL => CURLPROTO_HTTP,
            CURLINFO_PRIVATE => 'keep-me', CURLINFO_SSL_VERIFYRESULT => 0, CURLINFO_FILETIME => -1,
        ] as $option => $expected) {
            if (curl_getinfo($ch, $option) !== $expected) {
                throw new RuntimeException('Incorrect getinfo option ' . $option . ': ' . var_export(curl_getinfo($ch, $option), true));
            }
        }
        if (curl_getinfo($ch, CURLINFO_LOCAL_PORT) <= 0 || $info['header_size'] <= 0
            || $info['request_size'] !== strlen($info['request_header']) + 7
            || $info['namelookup_time'] < 0 || $info['connect_time'] < 0
            || $info['pretransfer_time'] < $info['connect_time']
            || $info['starttransfer_time'] <= $info['pretransfer_time']
            || $info['total_time'] < $info['starttransfer_time']
            || curl_getinfo($ch, CURLINFO_SPEED_DOWNLOAD) <= 0 || curl_getinfo($ch, CURLINFO_SPEED_UPLOAD) <= 0) {
            throw new RuntimeException('Missing transfer statistics: ' . var_export([$info, strlen($info['request_header']),
                curl_getinfo($ch, CURLINFO_LOCAL_PORT), curl_getinfo($ch, CURLINFO_SPEED_DOWNLOAD), curl_getinfo($ch, CURLINFO_SPEED_UPLOAD)], true));
        }
        // The PHP hook only collects timings directly available in the HTTP client.
        if ($mode === SWOOLE_HOOK_CURL) {
            foreach (['namelookup_time', 'connect_time', 'appconnect_time'] as $key) {
                if ($info[$key] !== 0.0) {
                    throw new RuntimeException('Unsupported connection timing must remain zero: ' . $key);
                }
            }
        } elseif ($info['connect_time'] <= 0) {
            throw new RuntimeException('Missing native connection timing');
        }
        foreach (['TOTAL_TIME', 'CONNECT_TIME', 'PRETRANSFER_TIME', 'STARTTRANSFER_TIME'] as $name) {
            $integerOption = 'CURLINFO_' . $name . '_T';
            if (defined($integerOption)) {
                $integer = curl_getinfo($ch, constant($integerOption));
                if (!is_int($integer) || abs($integer - curl_getinfo($ch, constant('CURLINFO_' . $name)) * 1000000) > 2) {
                    throw new RuntimeException('Incorrect integer timing option');
                }
            }
        }
        foreach (['SIZE_DOWNLOAD' => 4, 'SIZE_UPLOAD' => 7] as $name => $expected) {
            if (defined('CURLINFO_' . $name . '_T') && curl_getinfo($ch, constant('CURLINFO_' . $name . '_T')) !== $expected) {
                throw new RuntimeException('Incorrect integer transfer size');
            }
        }
        curl_setopt($ch, CURLOPT_URL, 'http://127.0.0.1:' . $reserved->getsockname()['port'] . '/');
        if (curl_exec($ch) !== false || curl_errno($ch) !== CURLE_COULDNT_CONNECT) {
            throw new RuntimeException('Connection unexpectedly succeeded');
        }
        $failed = curl_getinfo($ch);
        foreach (['http_code' => 0, 'content_type' => null, 'header_size' => 0, 'request_size' => 0,
            'size_download' => 0.0, 'size_upload' => 0.0] as $key => $expected) {
            if ($failed[$key] !== $expected) {
                throw new RuntimeException('Stale transfer field ' . $key . ': ' . var_export($failed[$key], true));
            }
        }
        if (curl_getinfo($ch, CURLINFO_PRIVATE) !== 'keep-me') {
            throw new RuntimeException('Clearing transfer statistics erased private data');
        }
        curl_setopt($ch, CURLOPT_URL, $url);
        if (curl_exec($ch) !== 'BODY' || curl_errno($ch) !== CURLE_OK
            || curl_getinfo($ch, CURLINFO_PRIMARY_PORT) !== $server->port) {
            throw new RuntimeException('Connection statistics affected the configured port');
        }
        curl_close($ch);
    } finally {
        $reserved->close();
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

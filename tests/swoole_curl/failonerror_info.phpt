--TEST--
swoole_curl: PHP hook preserves response information on FAILONERROR
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
        $response->status((int) ($request->get['code'] ?? 200));
        $response->header('Content-Type', 'text/plain');
        $response->header('Last-Modified', 'Wed, 21 Oct 2015 07:28:00 GMT');
        if (isset($request->get['redirect'])) {
            $response->status(302);
            $response->header('Location', '/?code=' . $request->get['code']);
        }
        $response->end('response-body');
    });
    Coroutine::create(fn () => $server->start());
    $origin = 'http://127.0.0.1:' . $server->port;
    try {
        $ch = curl_init($origin . '/?code=404');
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FAILONERROR => true, CURLOPT_TIMEOUT => 5]);
        if (curl_exec($ch) !== false || curl_errno($ch) !== CURLE_HTTP_RETURNED_ERROR
            || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 404
            || curl_getinfo($ch)['http_code'] !== 404) {
            throw new RuntimeException('A fresh handle lost the failure HTTP code');
        }
        curl_setopt($ch, CURLOPT_URL, $origin . '/?code=200');
        if (curl_exec($ch) !== 'response-body' || curl_errno($ch) !== CURLE_OK || curl_error($ch) !== ''
            || curl_getinfo($ch)['http_code'] !== 200) {
            throw new RuntimeException('A failed response poisoned the next successful request');
        }
        curl_close($ch);
        foreach ([400, 404, 500] as $code) {
            foreach ([false, true] as $redirect) {
                $headers = '';
                $ch = curl_init($origin . '/?code=200');
                if (!$ch instanceof Handler) {
                    throw new RuntimeException('Expected the PHP curl hook');
                }
                curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_FOLLOWLOCATION => true, CURLOPT_FAILONERROR => true, CURLOPT_TIMEOUT => 5,
                    CURLOPT_FILETIME => true, CURLINFO_HEADER_OUT => true,
                    CURLOPT_HEADERFUNCTION => function ($ch, $header) use (&$headers) {
                        $headers .= $header;
                        return strlen($header);
                    }]);
                if (curl_exec($ch) !== 'response-body') {
                    throw new RuntimeException('Initial successful request failed');
                }
                $url = $origin . '/?code=' . $code;
                curl_setopt($ch, CURLOPT_URL, $url . ($redirect ? '&redirect=1' : ''));
                $headers = '';
                if (curl_exec($ch) !== false || curl_errno($ch) !== CURLE_HTTP_RETURNED_ERROR) {
                    throw new RuntimeException('FAILONERROR did not fail');
                }
                $info = curl_getinfo($ch);
                if ($info['http_code'] !== $code || $info['content_type'] !== 'text/plain'
                    || $info['total_time'] <= 0 || $info['header_size'] <= 0
                    || $info['url'] !== $url || $info['redirect_count'] !== (int) $redirect
                    || $info['filetime'] !== 1445412480
                    || !str_contains($headers, ' ' . $code . ' ')
                    || !str_contains($info['request_header'], 'GET /?code=' . $code . ' ')) {
                    throw new RuntimeException('Missing failure response information: ' . var_export($info, true));
                }
            }
        }
        $ch = curl_init($origin . '/?code=404');
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5]);
        if (curl_exec($ch) !== 'response-body' || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 404) {
            throw new RuntimeException('FAILONERROR default changed');
        }
        curl_setopt_array($ch, [CURLOPT_FAILONERROR => true, CURLOPT_RETURNTRANSFER => false]);
        ob_start();
        $result = curl_exec($ch);
        $output = ob_get_clean();
        if ($result !== false || $output !== '' || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 404) {
            throw new RuntimeException('Failed response body was printed');
        }
        $file = tmpfile();
        curl_setopt($ch, CURLOPT_FILE, $file);
        if (curl_exec($ch) !== false || ftell($file) !== 0) {
            throw new RuntimeException('Failed response body was written to a file');
        }
        fclose($file);
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE

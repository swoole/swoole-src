--TEST--
swoole_curl: PHP and native hooks deliver only eligible response bodies to WRITEFUNCTION
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
            $response->status(302);
            $response->header('Location', '/');
            $response->end('REDIRECT');
        } elseif (isset($request->get['fail'])) {
            $response->status(404);
            $response->end('NOT_FOUND');
        } else {
            $response->end('FINAL');
        }
    });
    Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $check = function ($suffix, $follow, $fail, $expectedBody, $expectedError, $abort = false) use ($url) {
        $received = '';
        $ch = curl_init($url . $suffix);
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2,
            CURLOPT_FOLLOWLOCATION => $follow, CURLOPT_FAILONERROR => $fail,
            CURLOPT_WRITEFUNCTION => function ($ch, $data) use (&$received, $abort) {
                $received .= $data;
                return $abort ? 0 : strlen($data);
            }]);
        $result = curl_exec($ch);
        if ($result !== ($expectedError ? false : true) || curl_errno($ch) !== $expectedError || $received !== $expectedBody) {
            throw new RuntimeException('Unexpected write delivery: ' . var_export([$suffix, $result, curl_errno($ch), $received], true));
        }
        curl_close($ch);
    };
    try {
        $check('?redirect=1', true, false, 'FINAL', CURLE_OK);
        $check('?redirect=1', false, false, 'REDIRECT', CURLE_OK);
        $check('?fail=1', false, true, '', CURLE_HTTP_RETURNED_ERROR);
        $check('?fail=1', false, false, 'NOT_FOUND', CURLE_OK);
        $check('?fail=1', false, true, '', CURLE_HTTP_RETURNED_ERROR, true);
        $check('?redirect=1', true, false, 'FINAL', CURLE_WRITE_ERROR, true);

        // CURLOPT_RETURNTRANSFER selected after a callback restores buffered delivery.
        $received = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_TIMEOUT => 2,
            CURLOPT_WRITEFUNCTION => function ($ch, $data) use (&$received) {
                $received .= $data;
                return strlen($data);
            }, CURLOPT_RETURNTRANSFER => true]);
        if (curl_exec($ch) !== 'FINAL' || $received !== '') {
            throw new RuntimeException('RETURNTRANSFER did not replace the write callback');
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

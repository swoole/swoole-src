--TEST--
swoole_curl: PHP hook respects false method options and NOBODY option ordering
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
    $requests = [];
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) use (&$requests) {
        $requests[] = [$request->server['request_method'], $request->getContent()];
        $response->end('OK');
    });
    Coroutine::create(fn () => $server->start());
    $url = 'http://127.0.0.1:' . $server->port . '/';
    $check = function ($options, $expected) use ($url, &$requests) {
        $ch = curl_init($url);
        if (!$ch instanceof Handler) {
            throw new RuntimeException('Expected the PHP curl hook');
        }
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
        foreach ($options as [$option, $value]) {
            curl_setopt($ch, $option, $value);
        }
        $requests = [];
        $result = curl_exec($ch);
        if ($requests !== [$expected] || $result !== ($expected[0] === 'HEAD' ? '' : 'OK')) {
            throw new RuntimeException('Unexpected method: ' . var_export([$options, $requests, $result, curl_error($ch)], true));
        }
        curl_close($ch);
    };
    try {
        foreach ([false, 0, '0'] as $disabled) {
            $check([[CURLOPT_NOBODY, $disabled]], ['GET', '']);
            $check([[CURLOPT_NOBODY, true], [CURLOPT_NOBODY, $disabled]], ['GET', '']);
            $check([[CURLOPT_POSTFIELDS, 'payload'], [CURLOPT_NOBODY, $disabled]], ['POST', 'payload']);
            $check([[CURLOPT_POSTFIELDS, 'payload'], [CURLOPT_POST, $disabled]], ['GET', '']);
            $check([[CURLOPT_POSTFIELDS, 'payload'], [CURLOPT_POST, $disabled], [CURLOPT_POST, true]], ['POST', 'payload']);
            $check([[CURLOPT_NOBODY, true], [CURLOPT_POST, $disabled]], ['HEAD', '']);
            $check([[CURLOPT_UPLOAD, true], [CURLOPT_UPLOAD, $disabled]], ['GET', '']);
        }
        $check([[CURLOPT_NOBODY, true], [CURLOPT_POSTFIELDS, 'payload']], ['HEAD', '']);
        $check([[CURLOPT_NOBODY, true], [CURLOPT_POSTFIELDS, 'payload'], [CURLOPT_NOBODY, false]], ['POST', 'payload']);
        $check([[CURLOPT_NOBODY, true], [CURLOPT_POSTFIELDS, 'payload'], [CURLOPT_POST, true]], ['POST', 'payload']);
        $check([[CURLOPT_NOBODY, true], [CURLOPT_HTTPGET, false]], ['HEAD', '']);
        $check([[CURLOPT_NOBODY, true], [CURLOPT_HTTPGET, true]], ['GET', '']);
        $check([[CURLOPT_CUSTOMREQUEST, 'PATCH'], [CURLOPT_POSTFIELDS, 'payload'], [CURLOPT_POST, false]], ['PATCH', '']);

        // Switching options between executions must also update an existing HTTP client.
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
        foreach ([
            [CURLOPT_NOBODY, true, ['HEAD', '']],
            [CURLOPT_NOBODY, false, ['GET', '']],
            [CURLOPT_POSTFIELDS, 'payload', ['POST', 'payload']],
            [CURLOPT_NOBODY, false, ['POST', 'payload']],
            [CURLOPT_POST, false, ['GET', '']],
            [CURLOPT_POST, true, ['POST', 'payload']],
        ] as [$option, $value, $expected]) {
            curl_setopt($ch, $option, $value);
            $requests = [];
            $result = curl_exec($ch);
            if ($requests !== [$expected] || $result !== ($expected[0] === 'HEAD' ? '' : 'OK')) {
                throw new RuntimeException('Reused handle retained the previous method');
            }
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

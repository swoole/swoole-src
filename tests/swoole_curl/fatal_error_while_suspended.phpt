--TEST--
swoole_curl: fatal error while easy and multi handles are suspended
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Runtime;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

// The listener and accepted connections stay open until shutdown, so neither request completes.
$server = stream_socket_server('tcp://127.0.0.1:0');
stream_set_blocking($server, false);
$url = 'http://' . stream_socket_get_name($server, false) . '/';
$connections = [];

Coroutine\run(static function () use ($server, $url, &$connections): void {
    Coroutine::create(static function () use ($url): void {
        curl_exec(curl_init($url));
    });
    Coroutine::create(static function () use ($url): void {
        $multi = curl_multi_init();
        curl_multi_add_handle($multi, curl_init($url));
        do {
            curl_multi_exec($multi, $running);
            curl_multi_select($multi, 10);
        } while ($running);
    });

    // Once both requests have arrived, both coroutines are suspended in curl.
    $requests = [];
    $deadline = microtime(true) + 5;
    while (count($requests) < 2 || substr_count(implode('', $requests), "\r\n\r\n") < 2) {
        if ($connection = @stream_socket_accept($server, 0)) {
            stream_set_blocking($connection, false);
            $connections[] = $connection;
            $requests[] = '';
        }
        foreach ($connections as $index => $connection) {
            $requests[$index] .= fread($connection, 8192);
        }
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('requests were not sent');
        }
        Coroutine::sleep(0.001);
    }

    throw new RuntimeException('requests in flight');
});
?>
--EXPECTF--
Fatal error: Uncaught RuntimeException: requests in flight in %s:%d
Stack trace:
#0 [internal function]: {closure%s}()
#1 {main}
  thrown in %s on line %d

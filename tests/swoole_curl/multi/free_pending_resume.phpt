--TEST--
swoole_curl/multi: free multi handle with a pending resume
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--ENV--
USE_ZEND_ALLOC=0
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

// USE_ZEND_ALLOC=0 above makes the freed Multi allocation reach malloc(3),
// so a use-after-free crashes reliably instead of staying inside Zend MM.

use Swoole\Coroutine;
use Swoole\Event;
use Swoole\Runtime;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

$server = stream_socket_server('tcp://127.0.0.1:0');
stream_set_blocking($server, false);
$address = stream_socket_get_name($server, false);

Coroutine\run(static function () use ($server, $address): void {
    $multi = curl_multi_init();
    $handle = curl_init('http://' . $address . '/');
    curl_multi_add_handle($multi, $handle);

    $connection = false;
    $request = '';
    $deadline = microtime(true) + 1;
    do {
        curl_multi_exec($multi, $running);
        if (!$connection) {
            $connection = @stream_socket_accept($server, 0);
            if ($connection) {
                stream_set_blocking($connection, false);
            }
        }
        if ($connection) {
            $chunk = fread($connection, 8192);
            if ($chunk !== false) {
                $request .= $chunk;
            }
        }
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('request was not sent');
        }
    } while (!str_contains($request, "\r\n\r\n"));

    // Reactor end callbacks run timers before defer tasks, so blocking the reactor
    // here guarantees that the 1ms select timeout has expired before the readable
    // socket is observed. The socket event then queues a deferred resume for the
    // still-suspended coroutine, and the timeout resumes it right afterwards.
    Event::defer(static function () use ($connection): void {
        fwrite($connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        usleep(3000);
    });

    $selected = curl_multi_select($multi, 0.001);
    curl_multi_remove_handle($multi, $handle);
    unset($multi);

    // Reuse the freed Multi allocation so the pending deferred resume dereferences
    // poisoned memory instead of stale-but-valid data on unfixed builds.
    $strings = [];
    for ($index = 0; $index < 64; ++$index) {
        $strings[] = str_repeat(chr(65 + $index % 26), 160 + $index);
    }
    Coroutine::sleep(0.01);

    echo $selected, "\n";
    fclose($connection);
});

fclose($server);
?>
--EXPECT--
1

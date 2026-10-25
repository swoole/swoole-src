--TEST--
swoole_curl: curl_reset() releases callbacks, private data and post fields
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $ch = curl_init();
    $references = [];

    $write = new stdClass();
    $references['write'] = WeakReference::create($write);
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $data) use ($write) {
        return strlen($data);
    });

    $header = new stdClass();
    $references['header'] = WeakReference::create($header);
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $data) use ($header) {
        return strlen($data);
    });

    $read = new stdClass();
    $references['read'] = WeakReference::create($read);
    curl_setopt($ch, CURLOPT_READFUNCTION, function ($ch, $fd, $length) use ($read) {
        return '';
    });

    $private = new stdClass();
    $references['private'] = WeakReference::create($private);
    curl_setopt($ch, CURLOPT_PRIVATE, $private);

    $file = new CURLStringFile('data', 'data.txt');
    $references['postfields'] = WeakReference::create($file);
    curl_setopt($ch, CURLOPT_POSTFIELDS, ['file' => $file]);

    unset($write, $header, $read, $private, $file);
    curl_reset($ch);
    gc_collect_cycles();

    foreach ($references as $name => $reference) {
        echo $name, ': ', $reference->get() === null ? 'released' : 'retained', "\n";
    }
    var_dump(curl_getinfo($ch, CURLINFO_PRIVATE));

    // a callback set after a reset is released by the next one
    $next = new stdClass();
    $reference = WeakReference::create($next);
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $data) use ($next) {
        return strlen($data);
    });
    unset($next);
    curl_reset($ch);
    gc_collect_cycles();
    echo 'next write: ', $reference->get() === null ? 'released' : 'retained', "\n";
});
?>
--EXPECT--
write: released
header: released
read: released
private: released
postfields: released
bool(false)
next write: released

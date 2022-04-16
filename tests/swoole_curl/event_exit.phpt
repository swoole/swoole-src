--TEST--
swoole_curl: event exit
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    go(function () {
        Co::sleep(0.1);
        Swoole\Event::exit();
    });

    foreach ([6, 7, 8] as $os) {
        foreach ([10, 11, 12] as $version) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => sprintf('https://rpm.nodesource.com/pub_%d.x/el/%d/x86_64/', $version, $os),
                CURLOPT_RETURNTRANSFER => true
            ]);
            $response = curl_exec($ch);
            curl_close($ch);
        }
    }
});
echo "Done\n";
?>
--EXPECT--
Done

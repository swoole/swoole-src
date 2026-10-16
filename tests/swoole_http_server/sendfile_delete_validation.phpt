--TEST--
swoole_http_server: SendFile deleteAfterSend keeps the file when validation fails before ownership
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/sendfile.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$file = tempnam('/tmp', 'swoole_sendfile_validation_');
file_put_contents($file, 'hello swoole');
$dir = sys_get_temp_dir();

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm, $file) {
    Assert::same(file_get_contents("http://127.0.0.1:{$pm->getFreePort()}"), 'DONE');
    // Validation rejected the calls before ownership moved to Swoole, so the file is intact.
    clearstatcache(true, $file);
    Assert::true(is_file($file));
    echo "DONE\n";
    $pm->kill();
    @unlink($file);
};
$pm->childFunc = function () use ($pm, $file, $dir) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($file, $dir) {
        foreach ([[-1, 0], [0, -1]] as [$offset, $length]) {
            try {
                $response->sendfile(make_sendfile($file, $offset, $length));
                Assert::true(false, 'Negative object ranges must be rejected');
            } catch (ValueError $e) {
                Assert::contains($e->getMessage(), 'must be greater than or equal to 0');
            }
        }
        Assert::false(@$response->sendfile(make_sendfile($dir)));
        $response->end('DONE');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE

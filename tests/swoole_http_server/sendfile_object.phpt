--TEST--
swoole_http_server: SendFile ranges, ownership, retry, and legacy calls
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\SendFile;

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $path = tempnam(sys_get_temp_dir(), 'swoole-sendfile-object-');
    file_put_contents($path, 'abcdefghij');
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $path) {
        foreach (['range' => 'cde', 'legacy' => 'defg', 'named' => 'ef', 'validation' => 'OK', 'retry' => 'abcdefghij'] as $route => $body) {
            Assert::same(file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/{$route}"), $body);
            clearstatcache(true, $path);
            Assert::true(is_file($path));
        }
        Assert::same(file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/delete"), 'abcdefghij');
        $deadline = microtime(true) + 5;
        do {
            clearstatcache(true, $path);
            if (!is_file($path)) {
                break;
            }
            usleep(1000);
        } while (microtime(true) < $deadline);
        Assert::false(is_file($path));
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $path, $mode) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
        $server->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('request', function ($request, $response) use ($server, $path) {
            $file = new SendFile($path);
            switch ($request->server['request_uri']) {
                case '/range':
                    $file->offset = 2;
                    $file->length = 3;
                    Assert::true($response->sendfile($file));
                    break;
                case '/legacy':
                    Assert::true($response->sendfile($path, 3, 4));
                    break;
                case '/named':
                    Assert::true($response->sendfile(filename: $path, offset: 4, length: 2, delete_file: false));
                    break;
                case '/validation':
                    $file->deleteAfterSend = true;
                    foreach ([
                        fn () => $response->sendfile($path . "\0suffix", delete_file: true),
                        fn () => $server->sendfile($request->fd, $path . "\0suffix", delete_file: true),
                    ] as $call) {
                        try {
                            $call();
                            Assert::true(false, 'A path containing NUL must not acquire cleanup ownership');
                        } catch (ValueError $e) {
                            Assert::contains($e->getMessage(), 'null bytes');
                        }
                    }
                    foreach ([
                        fn () => $response->sendfile($file, 0),
                        fn () => $server->sendfile($request->fd, $file, 0),
                        fn () => $response->sendfile($file, delete_file: true),
                        fn () => $response->sendfile($file, delete_file: false),
                        fn () => $server->sendfile($request->fd, $file, delete_file: true),
                        fn () => $server->sendfile($request->fd, $file, delete_file: false),
                    ] as $call) {
                        try {
                            $call();
                            Assert::true(false, 'Object options must not be mixed with positional ranges');
                        } catch (ValueError $e) {
                            Assert::contains($e->getMessage(), 'must not be provided');
                        }
                    }
                    $file->offset = 100;
                    Assert::false(@$response->sendfile($file));
                    $file->offset = 0;
                    $file->length = 11;
                    Assert::false(@$server->sendfile($request->fd, $file));
                    $response->end('OK');
                    break;
                case '/retry':
                    $file->deleteAfterSend = true;
                    Assert::false(@$server->sendfile(-1, $file));
                    $file->deleteAfterSend = false;
                    Assert::true($response->sendfile($file));
                    break;
                case '/delete':
                    $file->deleteAfterSend = true;
                    Assert::true($response->sendfile($file));
                    try {
                        $server->sendfile($request->fd, $file);
                        Assert::true(false, 'An owned file descriptor must not be resubmitted');
                    } catch (Error $e) {
                        Assert::contains($e->getMessage(), 'already transferred file cleanup ownership');
                    }
                    // PHP object destruction must not delete the file while a native send is pending.
                    unset($file);
                    break;
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE

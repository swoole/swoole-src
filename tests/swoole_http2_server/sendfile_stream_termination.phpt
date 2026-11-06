--TEST--
swoole_http2_server: stop sendfile when its stream ends during asynchronous file reading
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Event;

$file = tempnam(sys_get_temp_dir(), 'swoole_http2_body_');
$lockFile = tempnam(sys_get_temp_dir(), 'swoole_http2_lock_');
file_put_contents($file, str_repeat('A', 1024));
file_put_contents($lockFile, 'lock');

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach (['reset', 'close'] as $termination) {
        $workerErrors = new Swoole\Atomic;
        $pm = new ProcessManager;
        $pm->setWaitTimeout(3);
        $pm->parentFunc = function () use ($pm, $termination, $lockFile, $workerErrors) {
            $lock = fopen($lockFile, 'r');
            Assert::true(flock($lock, LOCK_EX));
            // Leave ample flow-control credit: this must not depend on the zero-window check.
            $client = http2_test_open_request($pm->getFreePort(), '/', 65535);
            Assert::true($pm->wait());

            if ($termination === 'reset') {
                fwrite($client, http2_test_frame(3, 0, 1, pack('N', 8)));
                fwrite($client, http2_test_frame(6, 0, 0, 'before!!'));
                $ack = http2_test_wait_for_frame($client, 6, 1);
                Assert::same($ack['payload'], 'before!!');
            } else {
                fclose($client);
                // onClose defers this wakeup until HTTP/2 session cleanup has finished.
                Assert::true($pm->wait());
            }

            Assert::true(flock($lock, LOCK_UN));
            fclose($lock);
            Assert::true($pm->wait());
            Assert::same($workerErrors->get(), 0);

            if ($termination === 'reset') {
                fwrite($client, http2_test_request_headers(3, '/health'));
                do {
                    $frame = http2_test_read_frame($client);
                    Assert::isArray($frame);
                    // The reset was processed before the read completed; no response may follow on stream 1.
                    Assert::notSame($frame['streamId'], 1);
                } while ($frame['type'] !== 0);
                Assert::same($frame['streamId'], 3);
                Assert::same($frame['payload'], 'K');
            } else {
                $client = http2_test_open_request($pm->getFreePort(), '/health', 65535);
                $data = http2_test_wait_for_frame($client, 0);
                Assert::same($data['payload'], 'K');
            }
            fclose($client);
            $pm->kill();
        };
        $pm->childFunc = function () use ($pm, $mode, $file, $lockFile, $workerErrors) {
            $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
            $server->set([
                'worker_num' => 1,
                'aio_core_worker_num' => 1,
                'aio_worker_num' => 1,
                'log_file' => '/dev/null',
                'open_http2_protocol' => true,
            ]);
            $server->on('WorkerStart', function () use ($pm) {
                $pm->wakeup();
            });
            $server->on('WorkerError', function () use ($workerErrors) {
                $workerErrors->add();
            });
            $server->on('Close', function () use ($pm) {
                Event::defer(function () use ($pm) {
                    $pm->wakeup();
                });
            });
            $server->on('Request', function ($request, $response) use ($pm, $file, $lockFile) {
                if ($request->server['request_uri'] === '/health') {
                    $response->end('K');
                    return;
                }
                // Occupy the only AIO thread with a lock held by the client process.
                Coroutine::create(function () use ($lockFile) {
                    Assert::same(System::readFile($lockFile, LOCK_EX), 'lock');
                });
                Event::defer(function () use ($pm) {
                    Assert::same(Coroutine::stats()['aio_task_num'], 2);
                    $pm->wakeup();
                });
                var_dump($response->sendfile($file));
                Assert::false($response->isWritable());
                $pm->wakeup();
            });
            $server->start();
        };
        $pm->childFirst();
        $pm->run();
    }
}
unlink($file);
unlink($lockFile);
?>
--EXPECT--
bool(false)
bool(false)
bool(false)
bool(false)

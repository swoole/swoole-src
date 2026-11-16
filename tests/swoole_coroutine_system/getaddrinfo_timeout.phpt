--TEST--
swoole_coroutine_system: getaddrinfo times out while queued behind a blocked async worker
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('posix_mkfifo');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

// A blocked FIFO reader makes the timeout deterministic without root, chroot or an external DNS server.
swoole_async_set(['aio_core_worker_num' => 1, 'aio_worker_num' => 1]);
Co::set(['hook_flags' => 0]);
$fifo = sys_get_temp_dir() . '/swoole-getaddrinfo-' . getmypid() . '.fifo';
Assert::true(posix_mkfifo($fifo, 0600));
try {
    Co\run(function () use ($fifo) {
        $finished = new Co\Channel(1);
        go(function () use ($fifo, $finished) {
            Assert::same(Co::readFile($fifo), 'DONE');
            $finished->push(true);
        });
        $result = Co\System::getaddrinfo(domain: 'localhost', timeout: 0.02);
        Assert::false($result);
        Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_TIMEDOUT);

        // Release the worker and wait for the timed-out request's eventual completion.
        $writer = fopen($fifo, 'w');
        Assert::resource($writer);
        Assert::same(fwrite($writer, 'DONE'), 4);
        fclose($writer);
        Assert::true($finished->pop(2));
    });
} finally {
    unlink($fifo);
}
echo "DONE\n";
?>
--EXPECT--
DONE

--TEST--
swoole_event: propagate UnwindExit from timer, defer, cycle and readable callbacks
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('proc_open');
?>
--FILE--
<?php
require __DIR__ . '/../include/unwind_exit.inc';

$callbacks = [
    'timer' => 'Swoole\\Timer::after(1, fn() => exit(23));',
    'defer' => 'Swoole\\Event::defer(fn() => exit(23)); Swoole\\Event::defer(fn() => print("unexpected callback\\n"));',
    'cycle' => <<<'PHP'
[$reader, $writer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
Swoole\Event::add($reader, fn() => print("unexpected callback\n"));
Swoole\Event::cycle(fn() => exit(23), true);
PHP,
    'readable' => <<<'PHP'
[$reader, $writer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
fwrite($writer, 'ready');
Swoole\Event::add($reader, fn() => exit(23));
PHP,
];
foreach ($callbacks as $name => $callback) {
    $result = run_unwind_exit_php(<<<'PHP'
swoole_async_set(['enable_coroutine' => false]);
register_shutdown_function(fn() => print("shutdown\n"));
PHP
        . $callback . "\nSwoole\\Event::wait(); echo \"unexpected continuation\\n\";");
    assert_unwind_exit($result, 23, "shutdown\n");
    echo "$name: OK\n";
}
$result = run_unwind_exit_php(<<<'PHP'
swoole_async_set(['enable_coroutine' => false]);
Swoole\Event::defer(fn() => exit(0));
Swoole\Event::wait();
echo "unexpected continuation\n";
PHP);
assert_unwind_exit($result, 0, '');
echo "exit zero: OK\n";
?>
--EXPECT--
timer: OK
defer: OK
cycle: OK
readable: OK
exit zero: OK

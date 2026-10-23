--TEST--
swoole_coroutine: transfer delayed OOM termination to the caller VM
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('proc_open');
skip_if_win();
skip_if_in_valgrind('requires the Zend memory limit');
skip('requires delayed OOM support', ini_get('memory_hard_limit_percent') === false);
?>
--FILE--
<?php
require __DIR__ . '/../include/unwind_exit.inc';
$cases = [
    'immediate' => 'Swoole\\Coroutine\\run(fn() => exhaust_memory());',
    'suspended' => <<<'PHP'
Swoole\Coroutine\run(function () {
    go(function () {
        Swoole\Coroutine::sleep(0.001);
        exhaust_memory();
    });
});
PHP,
    'nested' => 'Swoole\\Coroutine\\run(fn() => go(fn() => go(fn() => exhaust_memory())));',
    'defer' => 'Swoole\\Coroutine\\run(fn() => Swoole\\Coroutine::defer(fn() => exhaust_memory()));',
    'remaining defers' => <<<'PHP'
Swoole\Coroutine\run(function () {
    Swoole\Coroutine::defer(fn() => print("unexpected defer\n"));
    Swoole\Coroutine::defer(fn() => exhaust_memory());
});
PHP,
    'ready coroutines' => <<<'PHP'
Swoole\Coroutine\run(function () {
    go(function () {
        Swoole\Coroutine::sleep(0.001);
        exhaust_memory();
    });
    go(function () {
        Swoole\Coroutine::sleep(0.001);
        echo "unexpected resumed coroutine\n";
    });
});
PHP,
    'context destructor' => <<<'PHP'
Swoole\Coroutine\run(function () {
    go(function () {
        Swoole\Coroutine::sleep(0.001);
        Swoole\Coroutine::getContext()['object'] = new class {
            public function __destruct() {
                exhaust_memory();
            }
        };
    });
    go(fn() => Swoole\Coroutine::sleep(30));
});
PHP,
];
foreach ($cases as $name => $case) {
    $result = run_unwind_exit_php(<<<'PHP'
register_shutdown_function(fn() => print("shutdown\n"));
function exhaust_memory(): void {
    $data = [];
    while (true) {
        $data[] = str_repeat('x', 1024 * 1024);
    }
}
PHP
        . $case . ' echo "unexpected continuation\\n";');
    assert_unwind_exit($result, 255, "shutdown\n");
    echo "$name: OK\n";
}
?>
--EXPECT--
immediate: OK
suspended: OK
nested: OK
defer: OK
remaining defers: OK
ready coroutines: OK
context destructor: OK

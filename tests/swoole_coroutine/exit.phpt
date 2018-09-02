--TEST--
swoole_coroutine: exit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

$exit_status_list = [
    'undef',
    null,
    1,
    1.1,
    'exit',
    ['exit' => 'ok'],
    (object)['exit' => 'ok'],
    STDIN
];
$exit_status_list_copy = $exit_status_list;

function route()
{
    controller();
}

function controller()
{
    your_code();
}

function your_code()
{
    global $exit_status_list;
    co::sleep(.001);
    $exit_status = array_shift($exit_status_list);
    if ($exit_status === 'undef') {
        exit;
    } else {
        exit($exit_status);
    }
}

for ($i = 0; $i < count($exit_status_list); $i++) {
    go(function () {
        global $exit_status_list_copy;
        try {
            // in coroutine
            route();
        } catch (\Swoole\ExitException $e) {
            assert($e->getFlags() & SWOOLE_EXIT_IN_COROUTINE);
            $exit_status = array_shift($exit_status_list_copy);
            $exit_status = $exit_status === 'undef' ? null : $exit_status;
            assert($e->getStatus() === $exit_status);
            // exit coroutine
            return;
        }
        echo "never here\n";
    });
}

?>
--EXPECT--

--TEST--
swoole_coroutine: coro with args
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class TestCo
{
    public function foo(...$args)
    {
        co::sleep(0.001);
        $cid = go(function () {
            co::yield();
        });
        co::resume($cid);
        echo @$this->test;

        foreach ($args as $index => $arg) {
            $recv = new Chan;
            $send = new Chan;
            $data = $args[$index];
            go(function () use ($recv, $data) {
                co::sleep(0.001);
                $recv->push($data); // response
            });
            go(function () use ($send, $data) {
                $data = $send->pop();
                if (assert($data === $data)) {
                    co::sleep(0.001);
                    $send->push(true); // send ok
                }
            });
            $ret = $send->push($data);
            assert($ret);
            $response = $recv->pop();
            assert($response == $data);
        }
    }
}

$php_args = [
    'undef',
    null,
    true,
    false,
    1,
    1.1,
    'exit',
    ['exit' => 'ok'],
    (object)['exit' => 'ok'],
    STDIN,
    0
];

go([new TestCo, 'foo'], ...$php_args);

?>
--EXPECTF--

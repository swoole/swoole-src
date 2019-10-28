--TEST--
swoole_coroutine: call_user_func_array 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (getenv("SKIP_ONLINE_TESTS")) {
    die("skip online test");
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class A
{
    function bar()
    {
        echo "bar\n";
        co::sleep(.02);
        $result = co::gethostbyname('www.swoole.com');
        echo "end\n";
        return $result;
    }
}

go(function () {
    $a = new A;
    $result = call_user_func_array([$a, 'bar'], []);
    Assert::same($result, gethostbyname('www.swoole.com'));
});
swoole_event_wait();
?>
--EXPECT--
bar
end

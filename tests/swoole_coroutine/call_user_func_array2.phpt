--TEST--
swoole_coroutine: call_user_func_array 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
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
        $result = co::gethostbyname('www.tsinghua.edu.cn');
        echo "end\n";
        return $result;
    }
}

go(function () {
    $a = new A;
    $result = call_user_func_array([$a, 'bar'], []);
    Assert::same($result, gethostbyname('www.tsinghua.edu.cn'));
});
swoole_event_wait();
?>
--EXPECT--
bar
end

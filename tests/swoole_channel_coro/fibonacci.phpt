--TEST--
swoole_channel_coro: fibonacci
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
exit("skip for select");
 ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$c1 = new chan();
$c2 = new chan();
function fibonacci($c1, $c2)
{
    go(function () use ($c1, $c2) {
        $a = 0;
        $b = 1;
        while(1) {
            $read_list = [$c2];
            $write_list = [$c1];
            $result = chan::select($read_list, $write_list, 2);
            if ($write_list) {
                $t = $a + $b;
                $a = $b;
                $b = $t;
                $c1->push($a);
            }
            if ($read_list) {
                $ret = $c2->pop();
                if ($ret === 1) {
                    return 1;
                }
            }
        }
    });
}
$num = 10;
go(function () use ($c1, $c2, $num) {
    for ($i = 0; $i < $num; $i ++) {
        $ret = $c1->pop();
        echo "fibonacci @$i $ret\n";
    }
    $c2->push(1);
});
fibonacci($c1, $c2);
?>
--EXPECT--
fibonacci @0 1
fibonacci @1 1
fibonacci @2 2
fibonacci @3 3
fibonacci @4 5
fibonacci @5 8
fibonacci @6 13
fibonacci @7 21
fibonacci @8 34
fibonacci @9 55

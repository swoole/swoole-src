<?php
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
                $write_list[0]->push($a);
            }
            if ($read_list) {
                $ret = $read_list[0]->pop();
                if ($ret === 1) {
                    echo "quit\n";
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

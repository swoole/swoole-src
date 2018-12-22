<?php
foreach(range(1, 100) as $i) {
    go(function () use ($i) {
        if ($i % 9 == 7) {
            return;
        }
        while(true) {
            co::sleep(10);
            echo "CORO: $i\n";
        }
    });
}

go(function () {
    while(true) {
        co::sleep(3);
        $coros = Co::listCoroutines();
        $cids = iterator_to_array($coros );
        var_dump($cids);
    }
});

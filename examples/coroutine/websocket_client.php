<?php
// go(function () {
//     $cli = new Co\http\Client("127.0.0.1", 9501);
//     $ret = $cli->upgrade("/");

//     if ($ret) {
//         while(true) {
//             $cli->push("hello");
//             var_dump($cli->recv());
//             co::sleep(0.1);
//         }
//     }

// });
go(function () {
    $cli = new Co\http\Client("127.0.0.1", 9501);
    $cli->set([
        'timeout' => 1
    ]);
    $ret = $cli->upgrade("/");

    if (!$ret) {
        echo "ERROR\n";
        return;
    }
    var_dump($cli->recv());
    for ($i = 0; $i < 5; $i ++) {
        $cli->push("hello @$i");
        var_dump($cli->recv());
        co::sleep(0.1);
    }
});

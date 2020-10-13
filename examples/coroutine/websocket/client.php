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
Co\Run(function () {
    $cli = new Co\http\Client("127.0.0.1", 9501);
    $cli->set([
        'timeout' => 1
    ]);
    $ret = $cli->upgrade("/websocket");

    if (!$ret) {
        echo "ERROR\n";
        return;
    }

    $cli->push("websocket handshake 1\n");
    $cli->push("websocket handshake 2\n");

    var_dump($cli->recv());
    for ($i = 0; $i < 5; $i ++) {
        $cli->push("hello @$i");
        var_dump($cli->recv());
        co::sleep(0.1);
    }
});

<?php
go(function () {
    $cli = new Co\http\Client("127.0.0.1", 9501);
    $ret = $cli->upgrade("/");

    if ($ret) {          
        while(true) {
            $cli->push("hello");
            var_dump($cli->recv());
            co::sleep(0.1);
        }
    }
});

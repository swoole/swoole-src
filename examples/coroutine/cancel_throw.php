<?php
Co\run(function () {
    $cid = Co\go(function () {
            while (true) {
                sleep(1);
                echo "co 2 running\n";
            }
            var_dump('end');

    });

    sleep(3);
    Co::cancel($cid, true);

    sleep(2);
    echo "co 1 end\n";
});

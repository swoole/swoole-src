<?php
swoole_tracer_prof_begin(['root_path' => __DIR__]);

function sleep_n($time)
{
    Co::sleep($time);
}

Co\run(function () {
    Co\go(function () {
        sleep_n(0.1);
    });

    Co\go(function () {
        sleep_n(0.2);
    });

    sleep_n(0.3);
});

swoole_tracer_prof_end('./test.json');
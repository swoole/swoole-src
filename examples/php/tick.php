<?php
declare(ticks=10);

include __DIR__ . '/func.php';

register_tick_function(function () {
    echo "i\n";
    sleep(1);
});
test();
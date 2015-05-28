<?php
 
function xrange($start, $end, $step = 1) {
    for ($i = $start; $i <= $end; $i += $step) {
        echo __LINE__."\n";
        yield $i;
    }
}
 
foreach (xrange(1, 1000000) as $num) {
    echo __LINE__."\n";
	echo $num, "\n";
    sleep(1);
}

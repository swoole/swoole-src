<?php
$fp = fopen(__DIR__.'/output.txt', 'a');
Swoole\Process::daemon(1, 1, [null, $fp, $fp]);

sleep(1);

fwrite(STDOUT, "ERROR 1\n");
fwrite(STDOUT, "ERROR 2\n");
fwrite(STDOUT, "ERROR 3\n");

fwrite(STDERR, "ERROR 4\n");
fwrite(STDERR, "ERROR 5\n");
fwrite(STDERR, "ERROR 6\n");
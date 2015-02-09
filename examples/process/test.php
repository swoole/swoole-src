<?php
var_dump($argv);
$stdin = fopen("php://stdin", 'r');
echo "Master: ".fgets($stdin)."\n";

sleep(1);

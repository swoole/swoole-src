<?php
$fp = fopen(__DIR__ . "/a.txt", "w");
ftruncate($fp, filesize(__DIR__ . "/a.txt"));
fwrite($fp, str_repeat('A', 1024));
fwrite($fp, str_repeat('B', 1024));
fwrite($fp, str_repeat('C', 256)."\n");

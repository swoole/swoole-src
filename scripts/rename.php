<?php

$match = $argv[1];
$files = glob($match);
var_dump($files);

$regx = '/' . str_replace('*', '(.+)', $match) . '/';

$ext = pathinfo($regx, PATHINFO_EXTENSION);

foreach ($files as $file) {
    if (is_file($file)) {
        preg_match($regx, $file, $matches);
        $newName = $matches[1] . '.' . $ext;
        `git mv $file $newName`;
    }
}

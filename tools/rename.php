<?php

$dirs = glob('./src/*');

foreach ($dirs as $d) {
    $files = glob($d.'/*.c');
    foreach ($files as $f) {
        `git mv $f {$f}c`;
    }
}
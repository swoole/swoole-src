#!/usr/bin/env php
<?php
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/server/functions.php';

$app = new Symfony\Component\Console\Application(
    "============================================================\n" .
    "<info>Swoole(v-" . SWOOLE_VERSION . ") Benchmark Test Tool </info>\n" .
    "============================================================"
);
$app->add(new SwooleBench\Command\RunTest());
$app->run();


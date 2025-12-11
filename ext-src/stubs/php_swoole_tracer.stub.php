<?php

function swoole_tracer_leak_detect(int $threshold = 64): void {}
function swoole_tracer_prof_begin(?array $options = null): bool {}
function swoole_tracer_prof_end(string $output_file): bool {}
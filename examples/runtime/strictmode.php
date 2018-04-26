<?php
sleep(1);
echo "sleep 1\n";
Swoole\Runtime::enableStrictMode();
sleep(1);
echo "sleep 2\n";

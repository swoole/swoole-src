echo "rm swoole_runtime.lo"
rm swoole_runtime.lo
echo "rm library/*.h"
rm library/*.h
php tools/build-library.php
echo "done"
make
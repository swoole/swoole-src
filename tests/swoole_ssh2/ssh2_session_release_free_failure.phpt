--TEST--
SSH2 session free failures close the transport descriptor
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
skip_if_not_linux();
skip_if_command_not_found('cc');
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

function countSocketDescriptors(): int
{
    $count = 0;
    foreach (glob('/proc/self/fd/*') ?: [] as $path) {
        $target = @readlink($path);
        if ($target !== false && str_starts_with($target, 'socket:[')) {
            $count++;
        }
    }
    return $count;
}

if (($argv[1] ?? null) === 'child') {
    Co\run(function (): void {
        $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
        if ($session === false) {
            throw new RuntimeException('Failed to connect to the SSH fixture.');
        }

        $connected = countSocketDescriptors();
        ssh2_disconnect($session);

        var_dump(countSocketDescriptors() === $connected - 1);
    });
    exit;
}

$source = tempnam(sys_get_temp_dir(), 'swoole_ssh2_free_');
$library = $source . '.so';
file_put_contents($source, <<<'C'
#define _GNU_SOURCE
#include <link.h>
#include <stdint.h>
#include <string.h>

unsigned int la_version(unsigned int version)
{
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

static int fail_session_free(void *session)
{
    return -9;
}

uintptr_t la_symbind64(Elf64_Sym *sym,
                       unsigned int ndx,
                       uintptr_t *refcook,
                       uintptr_t *defcook,
                       unsigned int *flags,
                       const char *name)
{
    return strcmp(name, "libssh2_session_free") == 0 ? (uintptr_t) fail_session_free : sym->st_value;
}
C);

$command = sprintf(
    'cc -shared -fPIC -x c -o %s %s',
    escapeshellarg($library),
    escapeshellarg($source),
);
exec($command, $output, $status);
if ($status !== 0) {
    throw new RuntimeException('Failed to build the libssh2 fault-injection fixture.');
}

// PHP loads extensions with RTLD_DEEPBIND, so LD_PRELOAD cannot replace swoole.so's libssh2 binding.
$command = sprintf(
    'LD_AUDIT=%s %s -d report_memleaks=0 -d display_errors=1 -d log_errors=0 %s child 2>&1',
    escapeshellarg($library),
    escapeshellarg(PHP_BINARY),
    escapeshellarg(__FILE__),
);
passthru($command, $status);

unlink($library);
unlink($source);

if ($status !== 0) {
    throw new RuntimeException("Fault-injection child failed with status {$status}.");
}
?>
--EXPECTF--
Warning: ssh2_disconnect(): Unable to free SSH2 session(-9): %S; resources retained in %s on line %d
bool(true)

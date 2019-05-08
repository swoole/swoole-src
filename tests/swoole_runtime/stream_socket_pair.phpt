--TEST--
swoole_runtime: stream_socket_pair
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole\runtime::enableCoroutine();

$pipe = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

Co::create(function()use(&$pipe){
    foreach(range(0, 9) as $n) {
        printf("Write byte: %d\n", fwrite($pipe[0], 'hello world '.$n));
        Co::sleep(.01);
    } 
    fclose($pipe[0]);
});

Co::create(function()use(&$pipe){
    while ($buffer = fread($pipe[1], 1024)) {
        printf("Read byte: %d, beffer: %s\n", strlen($buffer), $buffer);
    }
    fclose($pipe[1]);
});


swoole_event_wait();
?>
--EXPECT--
Write byte: 13
Read byte: 13, beffer: hello world 0
Write byte: 13
Read byte: 13, beffer: hello world 1
Write byte: 13
Read byte: 13, beffer: hello world 2
Write byte: 13
Read byte: 13, beffer: hello world 3
Write byte: 13
Read byte: 13, beffer: hello world 4
Write byte: 13
Read byte: 13, beffer: hello world 5
Write byte: 13
Read byte: 13, beffer: hello world 6
Write byte: 13
Read byte: 13, beffer: hello world 7
Write byte: 13
Read byte: 13, beffer: hello world 8
Write byte: 13
Read byte: 13, beffer: hello world 9

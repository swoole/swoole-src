--TEST--
swoole_event: del after close
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;

Co::set(['log_level' => SWOOLE_LOG_ERROR]);

$cli = new Swoole\Client(SWOOLE_SOCK_TCP);

$cli->connect("www.qq.com", 80);

$fd = $cli->sock;

Event::add($fd, function($fd) use($cli) {
    $resp = fread($fp, 8192);
    swoole_event_del($fp);
    fclose($fp);
});

Event::write($fd, "GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");

$cli->close();

if (Event::isset($fd)) {
    if (!Event::del($fd)) {
        echo  "Unable to release fd {$fd} from EventLoop\n";
    } else {
        echo "FD {$fd} released from EventLoop\n";
    }
}

$eventNum = Swoole\Coroutine::stats()['event_num'];
var_dump($eventNum);

Event::wait();
?>
--EXPECTF--
FD %d released from EventLoop
int(0)

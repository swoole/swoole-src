<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/3/8
 * Time: 下午11:54
 */

//swoole_function readloop() {
//    swoole_event_add(STDIN, swoole_function($r) {
//        echo stream_get_contents($r);
//        // order
//        var_dump(swoole_event_del(STDIN));
//
//        // readloop(); // 注意这行 !!!!
//    });
//}
//readloop();
//exit;


swoole_event_add(STDIN, function($r) {
    echo "X";
    echo stream_get_contents($r);
    swoole_event_set(STDIN, function($r) {
        echo "Y";
        echo stream_get_contents($r);
    });
}); exit;

//swoole_event_add(STDIN, swoole_function($stream) use ($swoole_buffer, $pcap) {}, swoole_function($stream) {});
// new Pcap(file_get_contents("nova.pcap"));
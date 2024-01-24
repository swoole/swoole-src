<?php
Co::set([
    'trace_flags' => SWOOLE_TRACE_HTTP2,
    'log_level' => 0,
]);
Co\run(function () {
	$client = new Swoole\Coroutine\Http\Client('www.jd.com', 443, true);
    $client->set(['write_func' => function($client, $data) {
        var_dump(strlen($data));
    }]);
    $client->get('/');
    var_dump(strlen($client->getBody()));
    return 0;
});

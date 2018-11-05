<?php
go(function() {
	$c = new Co\Http\Client('pro-api.coinmarketcap.com', 443, true);
	$c->set(['ssl_host_name' => 'pro-api.coinmarketcap.com']);
	$c->get('/');
	var_dump($c->body, $c->headers);
});

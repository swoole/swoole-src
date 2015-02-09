<?

$ser= new swoole_websocket_server("0.0.0.0", 9502);

$ser-> set(array( 
	"work_num" => 1
));

$ser-> on( 'open', function($ser, $fd)
{
	echo "server:shakehand success with fd{$fd}\r\n";
});

$ser-> on( 'message', function( $ser, $fd, $data, $opcode, $fin)
{
	echo "receive from {$fd}:{$data},opcode:{$opcode},fin:{$fin}\r\n";
	$ser -> push( $fd, "this is server", WEBSOCKET_OPCODE_TEXT, 1 );
});

$ser-> on( 'close', function($ser, $fd)
{
	echo "client {$fd} closed\r\n";
});

$ser-> start();

?>

<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

/**
 * Very basic websocket client.
 * Supporting draft hybi-10. 
 * 
 * @author Simon Samtleben <web@lemmingzshadow.net>
 * @version 2011-10-18
 */

class WebsocketClient
{
	private $_host;
	private $_port;
	private $_path;
	private $_origin;
	private $_Socket = null;
	private $_connected = false;
	
	public function __construct() { }
	
	public function __destruct()
	{
		$this->disconnect();
	}

	public function sendData($data, $type = 'text', $masked = true)
	{
		if($this->_connected === false)
		{
			trigger_error("Not connected", E_USER_WARNING);
			return false;
		}
		if( !is_string($data)) {
			trigger_error("Not a string data was given.", E_USER_WARNING);
			return false;		
		}
		if (strlen($data) == 0)
		{
			return false;
		}
		$res = $this->_Socket->send($this->_hybi10Encode($data, $type, $masked));

		if($res === 0 || $res === false)
		{
			return false;
		}		

		$buf = $this->_Socket->recv(512);
		
		$out = $this->_hybi10Decode($buf);
		return $out['payload'];
	}
	
	public function recvData() {
		$buf = $this->_Socket->recv(512);
		$out = $this->_hybi10Decode($buf);
		return $out['payload'];
	}

	public function connect($host, $port, $path, $origin = false)
	{
		$this->_host = $host;
		$this->_port = $port;
		$this->_path = $path;
		$this->_origin = $origin;
		
		$key = base64_encode($this->_generateRandomString(16, false, true));				
		$header = "GET " . $path . " HTTP/1.1\r\n";
		$header.= "Host: ".$host.":".$port."\r\n";
		$header.= "Upgrade: websocket\r\n";
		$header.= "Connection: Upgrade\r\n";
		$header.= "Sec-WebSocket-Key: " . $key . "\r\n";
		if($origin !== false)
		{
			$header.= "Sec-WebSocket-Origin: " . $origin . "\r\n";
		}
		$header.= "Sec-WebSocket-Version: 13\r\n";			
		
		$this->_Socket = new swoole_client(SWOOLE_TCP, SWOOLE_SOCK_SYNC);
		$this->_Socket->connect($host, $port, 1);
		$this->_Socket->send($header."\r\n");
		$response = $this->_Socket->recv(1500);

		preg_match('#Sec-WebSocket-Accept:\s(.*)$#mU', $response, $matches);

		if ($matches) {
			$keyAccept = trim($matches[1]);
			$expectedResonse = base64_encode(pack('H*', sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
			$this->_connected = ($keyAccept === $expectedResonse) ? true : false;
		}

		return $this->_connected;
	}
	
	public function checkConnection()
	{
		$this->_connected = false;
		
		// send ping:
		$data = 'ping?';
		$this->_Socket->send($this->_hybi10Encode($data, 'ping', true));

		$response = $this->_Socket->recv(300);
		if(empty($response))
		{			
			return false;
		}
		$response = $this->_hybi10Decode($response);
		if(!is_array($response))
		{			
			return false;
		}
		if(!isset($response['type']) || $response['type'] !== 'pong')
		{			
			return false;
		}
		$this->_connected = true;
		return true;
	}


	public function disconnect()
	{
		$this->_connected = false;
		$this->_Socket->close();
	}
	
	public function reconnect()
	{
		sleep(10);
		$this->_connected = false;
		fclose($this->_Socket);
		$this->connect($this->_host, $this->_port, $this->_path, $this->_origin);		
	}

	private function _generateRandomString($length = 10, $addSpaces = true, $addNumbers = true)
	{  
		$characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"§$%&/()=[]{}';
		$useChars = array();
		// select some random chars:    
		for($i = 0; $i < $length; $i++)
		{
			$useChars[] = $characters[mt_rand(0, strlen($characters)-1)];
		}
		// add spaces and numbers:
		if($addSpaces === true)
		{
			array_push($useChars, ' ', ' ', ' ', ' ', ' ', ' ');
		}
		if($addNumbers === true)
		{
			array_push($useChars, rand(0,9), rand(0,9), rand(0,9));
		}
		shuffle($useChars);
		$randomString = trim(implode('', $useChars));
		$randomString = substr($randomString, 0, $length);
		return $randomString;
	}
	
	private function _hybi10Encode($payload, $type = 'text', $masked = true)
	{
		$frameHead = array();
		$frame = '';
		$payloadLength = strlen($payload);
		
		switch($type)
		{		
			case 'text':
				// first byte indicates FIN, Text-Frame (10000001):
				$frameHead[0] = 129;				
			break;			
		
			case 'close':
				// first byte indicates FIN, Close Frame(10001000):
				$frameHead[0] = 136;
			break;
		
			case 'ping':
				// first byte indicates FIN, Ping frame (10001001):
				$frameHead[0] = 137;
			break;
		
			case 'pong':
				// first byte indicates FIN, Pong frame (10001010):
				$frameHead[0] = 138;
			break;
		}
		
		// set mask and payload length (using 1, 3 or 9 bytes) 
		if($payloadLength > 65535)
		{
			$payloadLengthBin = str_split(sprintf('%064b', $payloadLength), 8);
			$frameHead[1] = ($masked === true) ? 255 : 127;
			for($i = 0; $i < 8; $i++)
			{
				$frameHead[$i+2] = bindec($payloadLengthBin[$i]);
			}
			// most significant bit MUST be 0 (close connection if frame too big)
			if($frameHead[2] > 127)
			{
				$this->close(1004);
				return false;
			}
		}
		elseif($payloadLength > 125)
		{
			$payloadLengthBin = str_split(sprintf('%016b', $payloadLength), 8);
			$frameHead[1] = ($masked === true) ? 254 : 126;
			$frameHead[2] = bindec($payloadLengthBin[0]);
			$frameHead[3] = bindec($payloadLengthBin[1]);
		}
		else
		{
			$frameHead[1] = ($masked === true) ? $payloadLength + 128 : $payloadLength;
		}

		// convert frame-head to string:
		foreach(array_keys($frameHead) as $i)
		{
			$frameHead[$i] = chr($frameHead[$i]);
		}
		if($masked === true)
		{
			// generate a random mask:
			$mask = array();
			for($i = 0; $i < 4; $i++)
			{
				$mask[$i] = chr(rand(0, 255));
			}
			
			$frameHead = array_merge($frameHead, $mask);			
		}						
		$frame = implode('', $frameHead);

		// append payload to frame:
		$framePayload = array();	
		for($i = 0; $i < $payloadLength; $i++)
		{		
			$frame .= ($masked === true) ? $payload[$i] ^ $mask[$i % 4] : $payload[$i];
		}

		return $frame;
	}
	
	private function _hybi10Decode($data)
	{
		$payloadLength = '';
		$mask = '';
		$unmaskedPayload = '';
		$decodedData = array();
		
		// estimate frame type:
		$firstByteBinary = sprintf('%08b', ord($data[0]));		
		$secondByteBinary = sprintf('%08b', ord($data[1]));
		$opcode = bindec(substr($firstByteBinary, 4, 4));
		$isMasked = ($secondByteBinary[0] == '1') ? true : false;
		$payloadLength = ord($data[1]) & 127;		
		
		switch($opcode)
		{
			// text frame:
			case 1:
				$decodedData['type'] = 'text';				
			break;
		
			case 2:
				$decodedData['type'] = 'binary';
			break;
			
			// connection close frame:
			case 8:
				$decodedData['type'] = 'close';
			break;
			
			// ping frame:
			case 9:
				$decodedData['type'] = 'ping';				
			break;
			
			// pong frame:
			case 10:
				$decodedData['type'] = 'pong';
			break;
			
			default:
				return false;
			break;
		}
		
		if($payloadLength === 126)
		{
		   $mask = substr($data, 4, 4);
		   $payloadOffset = 8;
		   $dataLength = bindec(sprintf('%08b', ord($data[2])) . sprintf('%08b', ord($data[3]))) + $payloadOffset;
		}
		elseif($payloadLength === 127)
		{
			$mask = substr($data, 10, 4);
			$payloadOffset = 14;
			$tmp = '';
			for($i = 0; $i < 8; $i++)
			{
				$tmp .= sprintf('%08b', ord($data[$i+2]));
			}
			$dataLength = bindec($tmp) + $payloadOffset;
			unset($tmp);
		}
		else
		{
			$mask = substr($data, 2, 4);	
			$payloadOffset = 6;
			$dataLength = $payloadLength + $payloadOffset;
		}	
		
		if($isMasked === true)
		{
			for($i = $payloadOffset; $i < $dataLength; $i++)
			{
				$j = $i - $payloadOffset;
				if(isset($data[$i]))
				{
					$unmaskedPayload .= $data[$i] ^ $mask[$j % 4];
				}
			}
			$decodedData['payload'] = $unmaskedPayload;
		}
		else
		{
			$payloadOffset = $payloadOffset - 4;
			$decodedData['payload'] = substr($data, $payloadOffset);
		}
		
		return $decodedData;
	}
}

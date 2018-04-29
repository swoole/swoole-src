<?php

/**
   * multiple curl requests in parallel 
   * @example curl_concurrency(['http://g.cn','http://baidu.com'])
   */
function curl_concurrency($arrayUrls )
{
	$curlH = curl_multi_init();

	foreach ($arrayUrls as $i => $url) {
	    	 $conn[$i]=curl_init($url);
		curl_setopt($conn[$i],CURLOPT_RETURNTRANSFER,1);
		curl_multi_add_handle ($curlH,$conn[$i]);
	}

	$active = null;

	do {
	    $mrc = curl_multi_exec($curlH, $active);
	} while ($mrc == CURLM_CALL_MULTI_PERFORM);

	while ($active && $mrc == CURLM_OK) {
	    if (curl_multi_select($curlH) != -1) {
			usleep(100);
		}
        do {
            $mrc = curl_multi_exec($curlH, $active);
        } while ($mrc == CURLM_CALL_MULTI_PERFORM);
	    
	}


	foreach ($arrayUrls as $i => $url) {
	      $res[$i]=curl_multi_getcontent($conn[$i]);
		curl_multi_remove_handle($curlH, $conn[$i]);
	      curl_close($conn[$i]);
	}

	curl_multi_close($curlH);

	return $res;
}

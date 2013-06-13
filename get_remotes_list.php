<?php
	$m = new Mongo();
	$db = $m->test;
	$c = $m->test->log;
	
	MongoCursor::$timeout = -1;
	$retval = $db->command(array("distinct" => 'log', "key" => "remote"));
	//$retval = $c->distinct("remote");
	var_dump($retval);
	file_put_contents('/root/script/data/remotes.json', implode("\n", $retval['values']));



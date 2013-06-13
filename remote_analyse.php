<?php
ini_set('memory_limit', '-1');
define('REMOTES_LIST', '/root/script/data/remotes.json');

$m = new Mongo();
$c = $m->test->log;

//file processing
$handle = @fopen(REMOTES_LIST, "r");
if ($handle) {
	$i = 0;
	while (!feof($handle)) { 
		$buffer = fgets($handle);

		$i++;
		if ($i < 100) continue;

		$query = array("remote" => rtrim($buffer));
		$entry = new stdClass();
		$entry->total_records = $c->count($query);
		$entry->raw_data = array(); //same remote's records
		$enrty->type_data = array(); //same type's records

		$cursor = $c->find($query);
		foreach ($cursor as $doc) {
			$entry->raw_data[] = $doc;

			if (!isset($entry->type_data[$doc['ctype']])){
				$entry->type_data[$doc['ctype']] = array();
			}

			//$entry->type_data[$doc['ctype']][] = $doc['uri'];
			$entry->type_data[$doc['ctype']][] = 1;
		}

		$entry->raw_data_count = count($entry->raw_data);

		echo rtrim($buffer) . "    total: {$entry->raw_data_count} \n";
		foreach ($entry->type_data as $t => $d) {
			$type_count = count($d);
			echo "{$t}: {$type_count} " . round(100 * $type_count / $entry->raw_data_count, 2) . "%\n";
		}
//		echo $doc['ctype'] . ' | ' . $doc['uri'] . "\n";
		

//		var_dump($entry);
//		break;
	}
	fclose($handle);
}

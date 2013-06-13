<?php

define('LOG_ORIG_DIR', '/home/uploadlog');
define('LOG_LOADED_DIR', '/home/uploadlog/loaded'); //which files have been load to db will be moved to here

main();


function main() {
    $dir = new DirectoryIterator(LOG_ORIG_DIR);
    foreach ($dir as $fileinfo) {
        if (strtolower(pathinfo($fileinfo->getFilename(), PATHINFO_EXTENSION)) == 'log'
            && $fileinfo->isReadable()) {
                trigger_error("================================================================");
                trigger_error("Processing file: {$fileinfo->getFilename()}");
                if (logfile2db($fileinfo->getPathname())) {
                    rename($fileinfo->getPathname(), str_replace(LOG_ORIG_DIR, LOG_LOADED_DIR, $fileinfo->getPathname()));
                }
        }
    }
}

/**
 * log file process
 */
function logfile2db($filename) {
	$line_count = 0;
	$time_spent = 0;
	//prepare db
    $m = new Mongo();
    //$db = $m->test;
    $collection = $m->test->log;

    //file processing
    $handle = @fopen($filename, "r");
    if ($handle) {
        $server_flag = substr(basename($filename), 0, 7); //log server name
		$time_spent = time();
        while (!feof($handle)) {
            $buffer = fgets($handle);

            if ($doc_one = log2doc($buffer)) {

				$doc_one['server'] = $server_flag;
				$doc_one['transaction'] = true;
				try {
                	$collection->insert($doc_one);
				} catch (MongoException $e) {
					echo $e . "\n";
					echo "Current File: {$filename}\n";
					echo "Current Line: {$buffer}\n";
					echo 'You can manually rollback using db.log.remove({"transaction" : true})' . "\n";
					exit;
				}
            }

            $line_count++;
            if ($line_count % 100000 == 0) trigger_error("Processed lines: {$line_count}");
            //break; //for debug
		}
		$collection->update(
			array("transaction" => true), 
			array('$unset' => array("transaction" => 1)),
			array("multiple" => true)
		); //remove transaction flag

		$time_spent = time() - $time_spent;
		trigger_error("Finish! Load {$line_count} lines in {$time_spent} seconds.");
        fclose($handle);
    } else return false;
    return true;

}


/**
 * log line to document *
 */
function log2doc($log_line) {
    if ($log_line == '') return false;
	$log_line =	iconv("utf-8", "utf-8//ignore", $log_line); //to strip invalid characters

    $orig_arr   = array_values(array_filter(explode(' ', rtrim($log_line)), 'empty_str_filter'));

    if (count($orig_arr) != 10 ) {
        echo $log_line;
        var_dump($orig_arr);
        trigger_error('PARSE LOG ENTRY FAILED', E_USER_ERROR );
        exit;
    }

    $sec        = floor($orig_arr[0]);
    $usec       = intval(($orig_arr[0] - $sec) * 1000);
    return array(
        'ts'        => new MongoDate($sec, $usec),
        'rsp_time'  => intval($orig_arr[1]),
        'client_ip' => $orig_arr[2],
        'result'    => $orig_arr[3],
        'tsize'     => intval($orig_arr[4]),
        'method'    => $orig_arr[5],
        'uri'       => $orig_arr[6],
        'remote'    => $orig_arr[8],
        'ctype'     => $orig_arr[9]
    );
}

function empty_str_filter($str) {
    return $str !== '';
}


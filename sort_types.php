<?php

define('DATA_FILE', "/root/script/data/ctypes.json");

$types = file(DATA_FILE);

sort($types);

file_put_contents(DATA_FILE, $types);

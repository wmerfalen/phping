<?php
    error_reporting(-1);
ini_set('display_errors',1);
    function my_callback(){
        echo "Pong" . PHP_EOL;
    }
    ping($argv[1],'eth0','my_callback');
?>

<?php
    function my_callback(){
        echo "Pong" . PHP_EOL;
    }
    //ping($argv[1],'eth0','my_callback');
    $pinger = new Phping();
    $pinger->setDevice('eth0');
    $pinger->ping('192.168.11.1','eth0','my_callback',3,69);
?>

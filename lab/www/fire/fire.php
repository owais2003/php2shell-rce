<?php
// PHP2Shell handler-mismatch gadget
class Logger {
    public $cmd;
    public function __destruct() {
        @system($this->cmd);
    }
}
session_start();
echo "FIRED_OK\n";

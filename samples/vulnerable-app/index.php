<?php
// DELIBERATELY vulnerable code. Do not use in production.
echo "Hello " . $_GET['name'];                                          // XSS002
include($_GET['page']);                                                 // INJ005
mysqli_query($db, "SELECT * FROM users WHERE id = " . $_GET['id']);    // INJ001

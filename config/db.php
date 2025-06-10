<?php
$servername = "localhost";
$username = "root";
$password = "Siya@2018";
$dbname = "attendance_db";

// Create connection
$dbConnection = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($dbConnection->connect_error) {
    die("Connection failed: " . $dbConnection->connect_error);
}

// Set charset to utf8mb4 for proper encoding
$dbConnection->set_charset("utf8mb4");
?>
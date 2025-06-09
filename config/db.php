<!-- 
// Database configuration
// define('DB_HOST', 'localhost');
// define('DB_USER', 'root');
// define('DB_PASS', 'Siya@2018');
// define('DB_NAME', 'attendance_db');

// Create connection using PDO
// try {
//     $db = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME, DB_USER, DB_PASS);
//     $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
//     $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
// } catch(PDOException $e) {
//     die("Database connection failed: " . $e->getMessage());
// }
// ?>

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
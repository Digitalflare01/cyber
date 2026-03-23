<?php
// Simple Installation Script for DAST Platform
$db_host = 'localhost';
$db_user = 'u197294049_cyber_security';
$db_pass = 'Parayulla@123';
$db_name = 'u197294049_cyber_admin';

echo "<h1>DAST & Remediation Platform Installer</h1>";

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Read schema
    $schema = file_get_contents(__DIR__ . '/database/schema.sql');

    $pdo->exec($schema);
    echo "<p>Tables imported successfully.</p>";

    echo "<h3>Installation Complete!</h3>";
    echo "<p>Please delete this <code>install.php</code> file for security.</p>";
    echo "<a href='./index.html'>Go to Dashboard</a>";
}
catch (PDOException $e) {
    echo "<p style='color:red;'>Error: " . $e->getMessage() . "</p>";
}
?>

<?php
// Simple Installation Script for DAST Platform
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';

echo "<h1>DAST & Remediation Platform Installer</h1>";

try {
    $pdo = new PDO("mysql:host=$db_host", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create database if not exists
    $pdo->exec("CREATE DATABASE IF NOT EXISTS cyber_dast");
    echo "<p>Database 'cyber_dast' created or already exists.</p>";
    
    $pdo->exec("USE cyber_dast");
    
    // Read schema
    $schema = file_get_contents(__DIR__ . '/database/schema.sql');
    
    $pdo->exec($schema);
    echo "<p>Tables imported successfully.</p>";
    
    echo "<h3>Installation Complete!</h3>";
    echo "<p>Please delete this <code>install.php</code> file for security.</p>";
    echo "<a href='frontend/dist/'>Go to Dashboard</a>";
} catch (PDOException $e) {
    echo "<p style='color:red;'>Error: " . $e->getMessage() . "</p>";
}
?>

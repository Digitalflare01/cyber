<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once '../config/database.php';
require_once '../engines/NmapWrapper.php';
require_once '../engines/NVDClient.php';
require_once '../engines/MobSFWrapper.php';
require_once '../engines/ZAPWrapper.php';

$request = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

// Simple router
$base_path = '/cyber/backend/api';
$alt_path = '/cyber/backend/api/index.php';

if ((strpos($request, $base_path . '/scan/start') === 0 || strpos($request, $alt_path . '/scan/start') === 0) && $method === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $type = $data['type'] ?? '';
    $identifier = $data['identifier'] ?? '';
    $name = $data['name'] ?? 'New Scan';
    
    if (empty($type) || empty($identifier)) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing type or identifier']);
        exit;
    }
    
    $db = Database::getConnection();
    
    try {
        // Create target
        $stmt = $db->prepare("INSERT INTO targets (type, identifier, name) VALUES (?, ?, ?)");
        $stmt->execute([$type, $identifier, $name]);
        $target_id = $db->lastInsertId();
        
        // Create scan record
        $stmt = $db->prepare("INSERT INTO scans (target_id, engine, status, start_time) VALUES (?, ?, 'running', NOW())");
        $stmt->execute([$target_id, $type]);
        $scan_id = $db->lastInsertId();
        
        // Background process simulation based on engine type
        $results = [];
        
        if ($type === 'iot') {
            $engine = new NmapWrapper();
            $results = $engine->scan($identifier);
        } elseif ($type === 'software') {
            $engine = new NVDClient();
            $results = $engine->searchVulnerabilities($identifier); // identifier should be e.g. "apache:http_server:2.4.49"
        } elseif ($type === 'web') {
            $engine = new ZAPWrapper();
            $results = $engine->scan($identifier);
        } elseif ($type === 'mobile') {
            $engine = new MobSFWrapper();
            $results = $engine->scan($identifier); // identifier would be filename
        }
        
        // Update scan status
        $rawOutput = json_encode($results);
        $stmt = $db->prepare("UPDATE scans SET status = 'completed', end_time = NOW(), raw_output = ? WHERE id = ?");
        $stmt->execute([$rawOutput, $scan_id]);
        
        // Insert vulnerabilities
        if (isset($results['vulnerabilities']) && is_array($results['vulnerabilities'])) {
            $stmt = $db->prepare("INSERT INTO vulnerabilities (scan_id, title, severity, description, cve_id, remediation_snippet) VALUES (?, ?, ?, ?, ?, ?)");
            foreach ($results['vulnerabilities'] as $vuln) {
                $stmt->execute([
                    $scan_id,
                    $vuln['title'] ?? 'Unknown',
                    $vuln['severity'] ?? 'info',
                    $vuln['description'] ?? '',
                    $vuln['cve_id'] ?? null,
                    $vuln['remediation'] ?? ''
                ]);
            }
        }
        
        echo json_encode(['success' => true, 'scan_id' => $scan_id, 'message' => 'Scan completed successfully']);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Server error: ' . $e->getMessage()]);
    }
} elseif ((strpos($request, $base_path . '/scan/results') === 0 || strpos($request, $alt_path . '/scan/results') === 0) && $method === 'GET') {
    $scan_id = $_GET['id'] ?? 0;
    
    $db = Database::getConnection();
    $stmt = $db->prepare("
        SELECT s.*, t.name, t.type, t.identifier 
        FROM scans s 
        JOIN targets t ON s.target_id = t.id 
        WHERE s.id = ?
    ");
    $stmt->execute([$scan_id]);
    $scan = $stmt->fetch();
    
    if (!$scan) {
        http_response_code(404);
        echo json_encode(['error' => 'Scan not found']);
        exit;
    }
    
    $stmt = $db->prepare("SELECT * FROM vulnerabilities WHERE scan_id = ?");
    $stmt->execute([$scan_id]);
    $vulnerabilities = $stmt->fetchAll();
    
    $scan['findings'] = $vulnerabilities;
    echo json_encode($scan);
} elseif ((strpos($request, $base_path . '/history') === 0 || strpos($request, $alt_path . '/history') === 0) && $method === 'GET') {
    $db = Database::getConnection();
    
    $stmt = $db->query("
        SELECT s.id, t.name, t.type, t.identifier, s.status, s.start_time,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id) as finding_count
        FROM scans s
        JOIN targets t ON s.target_id = t.id
        ORDER BY s.id DESC
        LIMIT 50
    ");
    $history = $stmt->fetchAll();
    
    echo json_encode(['history' => $history]);
} else {
    http_response_code(404);
    echo json_encode(['error' => 'Endpoint not found: ' . $request]);
}
?>

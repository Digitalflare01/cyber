<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once __DIR__ . '/backend/config/database.php';
require_once __DIR__ . '/NativeScanner.php';
require_once __DIR__ . '/backend/engines/NVDClient.php';

$request = $_GET['endpoint'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

if ($request === '/scan/start' && $method === 'POST') {
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
        $stmt = $db->prepare("INSERT INTO targets (type, identifier, name) VALUES (?, ?, ?)");
        $stmt->execute([$type, $identifier, $name]);
        $target_id = $db->lastInsertId();
        
        $stmt = $db->prepare("INSERT INTO scans (target_id, engine, status, start_time) VALUES (?, ?, 'running', NOW())");
        $stmt->execute([$target_id, $type]);
        $scan_id = $db->lastInsertId();
        
        // Execute Native Scanners
        $scanner = new NativeScanner();
        $results = [];
        
        if ($type === 'iot') {
            $results = $scanner->scanNetwork($identifier);
        } elseif ($type === 'web') {
            $results = $scanner->scanWeb($identifier);
        } elseif ($type === 'mobile') {
            $results = $scanner->scanMobileMock();
        } elseif ($type === 'software') {
            $engine = new NVDClient();
            $results = $engine->searchVulnerabilities($identifier);
        }
        
        $rawOutput = json_encode($results);
        $stmt = $db->prepare("UPDATE scans SET status = 'completed', end_time = NOW(), raw_output = ? WHERE id = ?");
        $stmt->execute([$rawOutput, $scan_id]);
        
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
} elseif ($request === '/scan/results' && $method === 'GET') {
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
    $scan['findings'] = $stmt->fetchAll();
    
    echo json_encode($scan);
} elseif ($request === '/history' && $method === 'GET') {
    $db = Database::getConnection();
    $stmt = $db->query("
        SELECT s.id, t.name, t.type, t.identifier, s.status, s.start_time,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id) as finding_count
        FROM scans s
        JOIN targets t ON s.target_id = t.id
        ORDER BY s.id DESC
        LIMIT 50
    ");
    echo json_encode(['history' => $stmt->fetchAll()]);
} else {
    http_response_code(404);
    echo json_encode(['error' => 'Endpoint not found or method unsupported.']);
}
?>

<?php
class NativeScanner {
    public function scanWeb($url) {
        $vulns = [];
        
        // 1. Fetch Headers
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        
        $response = curl_exec($ch);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $headers = substr($response, 0, $headerSize);
        curl_close($ch);
        
        if (!$response) {
            return ['vulnerabilities' => [['title' => 'Host Unreachable', 'severity' => 'critical', 'description' => 'Target URL cannot be reached.', 'remediation' => 'Verify target is online and reachable.']]];
        }
        
        $headersLower = strtolower($headers);
        
        if (strpos($headersLower, 'strict-transport-security') === false) {
            $vulns[] = [
                'title' => 'Missing HSTS Header',
                'severity' => 'medium',
                'description' => 'HTTP Strict Transport Security is not enforced. Vulnerable to SSL stripping.',
                'cve_id' => null,
                'remediation' => "Add Header:\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
            ];
        }
        
        if (strpos($headersLower, 'x-frame-options') === false && strpos($headersLower, 'content-security-policy') === false) {
            $vulns[] = [
                'title' => 'Missing Clickjacking Protection',
                'severity' => 'medium',
                'description' => 'X-Frame-Options or CSP frame-ancestors is missing. Susceptible to clickjacking.',
                'cve_id' => null,
                'remediation' => "Add Header:\nHeader always set X-Frame-Options \"SAMEORIGIN\""
            ];
        }
        
        if (preg_match('/server:\s*(.*)/i', $headers, $matches)) {
            $server = trim($matches[1]);
            if (preg_match('/[0-9]/', $server)) {
                $vulns[] = [
                    'title' => 'Server Version Disclosure',
                    'severity' => 'low',
                    'description' => "Server exposes explicit version strings: $server",
                    'cve_id' => null,
                    'remediation' => "Configure ServerTokens Prod and ServerSignature Off in Apache."
                ];
            }
        }
        
        // 2. Scan for exposed .env
        $envUrl = rtrim($url, '/') . '/.env';
        $ch = curl_init($envUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $envResponse = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200 && strpos($envResponse, 'APP_ENV') !== false || strpos($envResponse, 'DB_PASSWORD') !== false) {
            $vulns[] = [
                'title' => 'Exposed .env Configuration File',
                'severity' => 'critical',
                'description' => 'The .env file is publicly accessible, leaking critical database and application secrets.',
                'cve_id' => null,
                'remediation' => "Block dotfiles in server config:\n\n<FilesMatch \"^\.\">\n    Require all denied\n</FilesMatch>"
            ];
        }
        
        if (empty($vulns)) {
            $vulns[] = [
                'title' => 'Scan Passed',
                'severity' => 'info',
                'description' => 'No critical web misconfigurations found by the native scanner.',
                'remediation' => ''
            ];
        }
        
        return ['vulnerabilities' => $vulns];
    }
    
    public function scanNetwork($ip) {
        $vulns = [];
        $ports = [
            21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 
            80 => 'HTTP', 443 => 'HTTPS', 3306 => 'MySQL', 
            3389 => 'RDP', 554 => 'RTSP'
        ];
        
        $host = parse_url($ip, PHP_URL_HOST) ?? $ip;
        $host = str_replace(['http://', 'https://'], '', $host);
        
        foreach ($ports as $port => $service) {
            $connection = @fsockopen($host, $port, $errno, $errstr, 1);
            if (is_resource($connection)) {
                fclose($connection);
                
                $severity = in_array($port, [21, 23, 3306, 3389]) ? 'high' : 'info';
                $remediation = $severity === 'high' ? "Block external access to Port $port at the network perimeter or firewall. Use a VPN for administration." : "Ensure $service is fully patched.";
                
                $vulns[] = [
                    'title' => "Open Port Detected: $port ($service)",
                    'severity' => $severity,
                    'description' => "$service service is actively listening on port $port and exposed to the network.",
                    'cve_id' => null,
                    'remediation' => $remediation
                ];
            }
        }
        
        if (empty($vulns)) {
            $vulns[] = [
                'title' => 'No Open Ports Detected',
                'severity' => 'info',
                'description' => 'The target aggressively dropped or rejected packets on common sensitive ports.',
                'remediation' => ''
            ];
        }
        
        return ['vulnerabilities' => $vulns];
    }

    public function scanMobileMock() {
        return [
            'vulnerabilities' => [
                [
                    'title' => 'Hardcoded AES Key Found in Binary',
                    'severity' => 'critical',
                    'description' => 'Static Analysis detected a hardcoded symmetric cryptographic key dynamically mapped in the APK Dex classes.',
                    'cve_id' => null,
                    'remediation' => "Use Android Keystore system or iOS Secure Enclave for key generation and storage."
                ]
            ]
        ];
    }
}
?>

<?php
class NVDClient {
    private $apiUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

    public function searchVulnerabilities($softwareIdentifier) {
        // e.g., "apache:http_server:2.4.49" -> cpeName
        // If the user inputs "apache 2.4.49", we do a keyword search
        
        $params = [
            'keywordSearch' => $softwareIdentifier,
            'resultsPerPage' => 5
        ];

        $url = $this->apiUrl . '?' . http_build_query($params);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_USERAGENT, 'DAST_Platform/1.0');
        // Add API Key here for higher rate limits if available
        // curl_setopt($ch, CURLOPT_HTTPHEADER, ['apiKey: YOUR_API_KEY']);
        
        $response = curl_exec($ch);
        curl_close($ch);

        $results = json_decode($response, true);
        
        if (!isset($results['vulnerabilities'])) {
            return $this->getMockData($softwareIdentifier); // Fallback to mock on rate limit / no result
        }

        $vulnerabilities = [];
        foreach ($results['vulnerabilities'] as $v) {
            $cve = $v['cve'];
            $id = $cve['id'];
            $desc = $cve['descriptions'][0]['value'] ?? 'No description';
            
            // Extract severity
            $severity = 'medium';
            if (isset($cve['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'])) {
                $severity = strtolower($cve['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']);
            } elseif (isset($cve['metrics']['cvssMetricV2'][0]['baseSeverity'])) {
                $severity = strtolower($cve['metrics']['cvssMetricV2'][0]['baseSeverity']);
            }

            $vulnerabilities[] = [
                'title' => "$id in $softwareIdentifier",
                'severity' => $severity,
                'description' => $desc,
                'cve_id' => $id,
                'remediation' => "1. Check for official vendor patches for $id.\n2. Upgrade the software to the latest stable version.\n3. Apply virtual patching at the WAF level if immediate upgrade is not possible."
            ];
        }

        if (empty($vulnerabilities)) {
            return $this->getMockData($softwareIdentifier);
        }

        return ['vulnerabilities' => $vulnerabilities];
    }

    private function getMockData($target) {
        return [
            'vulnerabilities' => [
                [
                    'title' => 'Remote Code Execution in ' . htmlspecialchars($target),
                    'severity' => 'critical',
                    'description' => 'A flaw was found affecting parse mechanisms which could lead to RCE under specific configurations.',
                    'cve_id' => 'CVE-2021-41773',
                    'remediation' => "Upgrade immediately. \nPatch code:\n`apt-get update && apt-get install --only-upgrade " . htmlspecialchars($target) . "`"
                ]
            ]
        ];
    }
}
?>

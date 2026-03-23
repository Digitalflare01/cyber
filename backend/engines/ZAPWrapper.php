<?php
class ZAPWrapper {
    public function scan($targetUrl) {
        if (!filter_var($targetUrl, FILTER_VALIDATE_URL)) {
            throw new Exception("Invalid target URL");
        }

        return $this->getMockData($targetUrl);
    }

    private function getMockData($targetUrl) {
        return [
            'vulnerabilities' => [
                [
                    'title' => 'Cross-Site Scripting (Reflected)',
                    'severity' => 'high',
                    'description' => 'The page reflects user input directly into the HTML response without escaping, allowing arbitrary JavaScript execution.',
                    'cve_id' => null,
                    'remediation' => "Ensure rigorous output encoding.\n\nPHP Fix:\n`echo htmlspecialchars(\$input, ENT_QUOTES, 'UTF-8');`"
                ],
                [
                    'title' => 'SQL Injection',
                    'severity' => 'critical',
                    'description' => 'A parameter is directly concatenated into a SQL query without parameterization.',
                    'cve_id' => null,
                    'remediation' => "Use Prepared Statements.\n\nPHP Fix:\n`\$stmt = \$pdo->prepare('SELECT * FROM users WHERE username = ?');`\n`\$stmt->execute([\$username]);`"
                ]
            ]
        ];
    }
}
?>

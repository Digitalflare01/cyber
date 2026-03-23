<?php
class MobSFWrapper {
    public function scan($filename) {
        return $this->getMockData($filename);
    }

    private function getMockData($filename) {
        return [
            'vulnerabilities' => [
                [
                    'title' => 'Hardcoded API Key Found',
                    'severity' => 'critical',
                    'description' => 'MobSF detected a hardcoded AWS key inside strings.xml of the decompiled APK.',
                    'cve_id' => null,
                    'remediation' => "Remove keys from strings.xml. Use a secure backend to proxy AWS requests instead of embedding credentials."
                ],
                [
                    'title' => 'Insecure Data Storage',
                    'severity' => 'medium',
                    'description' => 'SharedPreferences are being used to store sensitive session tokens in plaintext.',
                    'cve_id' => null,
                    'remediation' => "Use EncryptedSharedPreferences (Android) or Keychain (iOS).\n\nAndroid Fix:\n`EncryptedSharedPreferences.create(\"secret_shared_prefs\", ...)`"
                ]
            ]
        ];
    }
}
?>

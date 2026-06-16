use regex::Regex;

/// Real response analyzer for detecting vulnerabilities using actual security patterns
#[derive(Clone)]
pub struct ResponseAnalyzer {
    baseline_response: Option<String>,
    baseline_time: Option<u64>,
    anomaly_threshold: f32,
}

#[derive(Debug, Clone)]
pub struct ResponseAnalysis {
    pub is_vulnerable: bool,
    pub confidence: f32,
    pub vulnerability_type: Vec<String>,
    pub evidence: Vec<String>,
    pub recommendations: Vec<String>,
}

impl ResponseAnalyzer {
    pub fn new(anomaly_threshold: f32) -> Self {
        Self {
            baseline_response: None,
            baseline_time: None,
            anomaly_threshold,
        }
    }

    pub fn set_baseline(&mut self, response: &str, response_time: u64) {
        self.baseline_response = Some(response.to_string());
        self.baseline_time = Some(response_time);
    }

    pub fn analyze(&self, response: &str, _response_time: u64) -> ResponseAnalysis {
        let mut analysis = ResponseAnalysis {
            is_vulnerable: false,
            confidence: 0.0,
            vulnerability_type: Vec::new(),
            evidence: Vec::new(),
            recommendations: Vec::new(),
        };

        // Check baseline anomaly detection using threshold
        if let Some(ref baseline) = self.baseline_response {
            let diff_score = self.calculate_difference(baseline, response);
            if diff_score > self.anomaly_threshold {
                analysis.evidence.push(format!("Response differs from baseline by {:.2}%", diff_score * 100.0));
            }
        }

        // SQL Injection Detection
        if let Some(confidence) = self.detect_sql_injection(response) {
            analysis.is_vulnerable = true;
            analysis.confidence = analysis.confidence.max(confidence);
            analysis.vulnerability_type.push("SQL Injection".to_string());
            analysis.evidence.push("SQL error patterns detected".to_string());
            analysis.recommendations.push("Use parameterized queries".to_string());
        }

        // XSS Detection
        if let Some(confidence) = self.detect_xss(response) {
            analysis.is_vulnerable = true;
            analysis.confidence = analysis.confidence.max(confidence);
            analysis.vulnerability_type.push("Cross-Site Scripting".to_string());
            analysis.evidence.push("XSS patterns detected".to_string());
            analysis.recommendations.push("Implement output encoding".to_string());
        }

        // Command Injection Detection
        if let Some(confidence) = self.detect_command_injection(response) {
            analysis.is_vulnerable = true;
            analysis.confidence = analysis.confidence.max(confidence);
            analysis.vulnerability_type.push("Command Injection".to_string());
            analysis.evidence.push("Command execution patterns detected".to_string());
            analysis.recommendations.push("Validate and sanitize input".to_string());
        }

        analysis
    }

    fn calculate_difference(&self, baseline: &str, response: &str) -> f32 {
        // Simple difference calculation based on length and content similarity
        let baseline_len = baseline.len();
        let response_len = response.len();
        
        if baseline_len == 0 {
            return if response_len > 0 { 1.0 } else { 0.0 };
        }
        
        // Calculate length difference ratio
        let len_diff = (baseline_len as i64 - response_len as i64).abs() as f32;
        let len_ratio = len_diff / baseline_len as f32;
        
        // Check for common substrings
        let common_prefix_len = baseline.chars().zip(response.chars()).take_while(|(a, b)| a == b).count();
        let prefix_ratio = 1.0 - (common_prefix_len as f32 / baseline_len.max(response_len) as f32);
        
        // Combine metrics
        (len_ratio + prefix_ratio) / 2.0
    }

    fn detect_sql_injection(&self, response: &str) -> Option<f32> {
        let mut confidence: f32 = 0.0;
        let lower_response = response.to_lowercase();

        // Only fire if actual SQL error context is present
        let has_sql_error = [
            "sql syntax", "mysql_fetch", "mysql_num_rows", "mysqli_",
            "ora-01", "ora-02", "sqlstate", "unclosed quotation",
            "odbc", "jdbc", "sqlite_", "microsoft ole db", "odbc driver",
            "column count", "operand should contain"
        ].iter().any(|e| lower_response.contains(e));

        if !has_sql_error {
            return None;
        }

        // Actual SQL injection patterns used by penetration testers
        let sql_patterns = [
            "union select", "or 1=1", "and 1=1", "'or '1'='1", "'or 1=1--",
            "admin'--", "'or 'x'='x", "insert into", "delete from", "drop table",
            "exec(", "xp_cmdshell", "sp_executesql"
        ];

        for pattern in sql_patterns {
            if lower_response.contains(pattern) {
                confidence = confidence.max(0.85);
            }
        }

        if confidence > 0.0 {
            Some(confidence)
        } else {
            None
        }
    }

    fn detect_xss(&self, response: &str) -> Option<f32> {
        // Only fire on explicitly reflected XSS payloads, not generic keywords
        let xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(\"XSS\")</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<script>alert(1)</script>",
        ];

        for payload in xss_payloads {
            if response.contains(payload) {
                return Some(0.95);
            }
        }

        None
    }

    fn detect_command_injection(&self, response: &str) -> Option<f32> {
        let lower_response = response.to_lowercase();

        // Require at least 2 indicators for a firing to reduce false positives
        let mut hits = 0usize;

        // Actual command output patterns
        let command_patterns = [
            "root:", "daemon:", "bin:", "sys:", "/bin/bash", "/bin/sh", "cmd.exe",
            "powershell", "system(", "exec(", "shell_exec(", "passthru(",
            "whoami", "uname", "id", "ps aux", "net user",
        ];

        for pattern in command_patterns {
            if lower_response.contains(pattern) {
                hits += 1;
            }
        }

        let file_patterns = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "c:\\boot.ini",
            "c:\\windows\\system32", "/proc/version", "no such file or directory",
            "permission denied", "access denied", "command not found"
        ];

        for pattern in file_patterns {
            if lower_response.contains(pattern) {
                hits += 1;
            }
        }

        if let Ok(backtick_regex) = Regex::new(r"`[^`]*`") {
            if backtick_regex.is_match(response) {
                hits += 1;
            }
        }

        if let Ok(semicol_regex) = Regex::new(r";\s*\b(cat|ls|dir|whoami|id|uname)\b") {
            if semicol_regex.is_match(response) {
                hits += 1;
            }
        }

        if hits >= 2 {
            Some(0.85f32.min(0.85 + 0.05 * (hits as f32 - 2.0)))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let analyzer = ResponseAnalyzer::new(0.5);
        let response = "You have an error in your SQL syntax near 'or 1=1'";
        let analysis = analyzer.analyze(response, 100);
        
        assert!(analysis.is_vulnerable);
        assert!(analysis.vulnerability_type.contains(&"SQL Injection".to_string()));
        assert!(analysis.confidence > 0.8);
    }

    #[test]
    fn test_xss_detection() {
        let analyzer = ResponseAnalyzer::new(0.5);
        let response = "<script>alert('XSS')</script>";
        let analysis = analyzer.analyze(response, 100);
        
        assert!(analysis.is_vulnerable);
        assert!(analysis.vulnerability_type.contains(&"Cross-Site Scripting".to_string()));
        assert!(analysis.confidence > 0.9);
    }

    #[test]
    fn test_command_injection_detection() {
        let analyzer = ResponseAnalyzer::new(0.5);
        let response = "root:x:0:0:root:/root:/bin/bash";
        let analysis = analyzer.analyze(response, 100);
        
        assert!(analysis.is_vulnerable);
        assert!(analysis.vulnerability_type.contains(&"Command Injection".to_string()));
        assert!(analysis.confidence > 0.8);
    }
}

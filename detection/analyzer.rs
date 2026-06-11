use serde::{Serialize, Deserialize};
use crate::core::scanner::ScanResult;
use crate::detection::matcher::Matcher;
use crate::detection::signatures::SignatureDatabase;
use crate::detection::behavior::BehaviorAnalyzer;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub url: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Finding {
    pub fn new(url: &str, severity: Severity, title: &str, description: &str) -> Self {
        Self {
            url: url.to_string(),
            severity,
            title: title.to_string(),
            description: description.to_string(),
            evidence: String::new(),
            remediation: String::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: &str) -> Self {
        self.evidence = evidence.to_string();
        self
    }

    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = remediation.to_string();
        self
    }
}

#[derive(Clone)]
pub struct Analyzer {
    matcher: Matcher,
    signatures: SignatureDatabase,
    behavior: BehaviorAnalyzer,
}

impl Analyzer {
    pub fn new() -> Self {
        let mut matcher = Matcher::new();
        let _ = matcher.add_pattern("custom_test", r"test\d+");
        let _has_sql = matcher.has_pattern("sql_error");
        Self {
            matcher,
            signatures: SignatureDatabase::new(),
            behavior: BehaviorAnalyzer::new(),
        }
    }

    fn is_waf_block(body: &str, status: u16) -> bool {
        let b = body.to_lowercase();
        if status != 403 && status != 503 && status != 429 {
            return false;
        }
        b.contains("cf-ray") || b.contains("cloudflare") ||
        b.contains("attention required") || b.contains("security check") ||
        b.split(|c: char| !c.is_alphanumeric()).any(|word| word == "ddos") ||
        (b.contains("waf-block") || b.contains("waf-denied"))
    }

    pub async fn analyze(&self, result: ScanResult) -> Option<Finding> {
        if result.status == 0 {
            return None;
        }

        if let Some(response) = &result.response {
            let body = &response.body;

            // Gate: skip all detection if response looks like WAF/CDN block
            if Self::is_waf_block(body, result.status) {
                return None;
            }

            let sent_probe = !result.payload.is_empty();

            if sent_probe && self.matcher.matches("sql_error", body) {
                let evidence = self.matcher.find_all("sql_error", body).join(", ");
                return Some(Finding::new(
                    &result.url,
                    Severity::High,
                    &format!("SQL Injection [{}]", result.payload),
                    "Database error patterns found in response",
                )
                .with_evidence(&evidence)
                .with_remediation("Use parameterized queries and input validation"));
            }

            if sent_probe && self.matcher.matches("xss_vulnerable", body) {
                return Some(Finding::new(
                    &result.url,
                    Severity::High,
                    &format!("XSS Vulnerability [{}]", result.payload),
                    "Cross-site scripting patterns found in response",
                )
                .with_remediation("Implement proper output encoding and CSP headers"));
            }

            if sent_probe && self.matcher.matches("path_traversal", body) {
                return Some(Finding::new(
                    &result.url,
                    Severity::Critical,
                    &format!("Path Traversal [{}]", result.payload),
                    "Path traversal patterns indicate file access vulnerability",
                )
                .with_remediation("Validate and sanitize file paths"));
            }

            if self.matcher.matches("private_key", body) {
                return Some(Finding::new(
                    &result.url,
                    Severity::Critical,
                    "Private Key Exposed",
                    "Private key material found in response",
                )
                .with_remediation("Remove private keys from public access"));
            }

            for (_, sig) in self.signatures.all() {
                if body.contains(&sig.pattern) {
                    return Some(
                        Finding::new(
                            &result.url,
                            severity_from_string(&sig.severity),
                            &sig.name,
                            &sig.description,
                        )
                        .with_remediation(&sig.remediation),
                    );
                }
            }

            if self.behavior.detect_error_page(body).is_some() {
                return Some(Finding::new(
                    &result.url,
                    Severity::Info,
                    "Error Page Detected",
                    "Application error page may reveal sensitive information",
                ));
            }

            if let Some(f) = self.check_common_vulns(&result, response).await { return Some(f); }
            if let Some(f) = self.check_info_disclosure(&result, response).await { return Some(f); }
            if let Some(f) = self.check_misconfigurations(&result, response).await { return Some(f); }
            // check_server_issues removed — 401/403/5xx are not vulnerabilities
        }

        None
    }

    async fn check_common_vulns(&self, result: &ScanResult, response: &crate::http::response::HttpResponse) -> Option<Finding> {
        let body = &response.body;
        let status = response.status;

        if result.url.split('/').any(|p| p == "admin") && status == 200
            && body.to_lowercase().contains("login")
            && (body.contains("type=\"password\"") || body.contains("type='password'"))
            && body.len() < 50000
        {
            return Some(Finding::new(
                &result.url,
                Severity::Medium,
                "Admin Panel Accessible",
                "The administrative interface is publicly accessible without authentication"
            ).with_remediation("Implement IP restrictions and strong authentication"));
        }

        if result.url.contains(".git/") && status == 200
            && body.contains("[core]")
            && (body.contains("repositoryformatversion") || body.contains("filemode"))
        {
            return Some(Finding::new(
                &result.url,
                Severity::High,
                "Git Repository Exposed",
                "Git repository files are publicly accessible"
            ).with_remediation("Remove .git directory from web root or block access"));
        }

        if self.contains_passwd_file(body) {
            return Some(Finding::new(
                &result.url,
                Severity::Critical,
                "Local File Inclusion",
                "Sensitive system files are being exposed"
            ).with_evidence("Found passwd file content in response"));
        }

        None
    }

    fn contains_passwd_file(&self, body: &str) -> bool {
        let lower = body.to_lowercase();
        if !lower.contains("root:x:0:0") || !lower.contains("/bin/") {
            return false;
        }
        let lines: Vec<&str> = lower.lines().collect();
        for line in &lines {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6
                && parts[2].parse::<u32>().is_ok()
                && parts[3].parse::<u32>().is_ok()
            {
                return true;
            }
        }
        false
    }

    async fn check_info_disclosure(&self, result: &ScanResult, response: &crate::http::response::HttpResponse) -> Option<Finding> {
        if let Some(server) = response.server_header() {
            if server.contains("Apache/2.4") || server.contains("nginx/1.") {
                return Some(Finding::new(
                    &result.url,
                    Severity::Low,
                    "Server Version Disclosure",
                    &format!("Server exposes version information: {}", server)
                ).with_remediation("Configure server to hide version information"));
            }
        }

        if let Some(powered) = response.powered_by() {
            if powered.chars().any(|c| c.is_ascii_digit()) {
                return Some(Finding::new(
                    &result.url,
                    Severity::Low,
                    "Framework Version Disclosure",
                    &format!("X-Powered-By header reveals: {}", powered)
                )
                .with_remediation("Configure server to hide version information"));
            }
        }

        None
    }

    async fn check_misconfigurations(&self, result: &ScanResult, response: &crate::http::response::HttpResponse) -> Option<Finding> {
        let body = &response.body;
        
        if body.contains("Index of /") || body.contains("Directory Listing") {
            return Some(Finding::new(
                &result.url,
                Severity::Medium,
                "Directory Listing Enabled",
                "Server allows directory listing which exposes file structure"
            ).with_remediation("Disable directory indexing in web server configuration"));
        }

        if body.contains("phpinfo()") && body.contains("<!DOCTYPE")
            || body.contains("PHP Version") && body.chars().any(|c| c.is_ascii_digit()) && body.contains("<!DOCTYPE") {
            return Some(Finding::new(
                &result.url,
                Severity::Medium,
                "PHP Information Disclosure",
                "phpinfo() page or PHP version information is exposed"
            ).with_remediation("Remove phpinfo() pages from production"));
        }

        None
    }

    // check_server_issues removed — 401/403/5xx status codes are not vulnerabilities
}

fn severity_from_string(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

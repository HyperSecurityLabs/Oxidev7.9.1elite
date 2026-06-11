use crate::detection::analyzer::Finding;

pub struct Confirm;

impl Confirm {
    pub fn confirm_vulnerability(finding: &Finding) -> bool {
        if finding.title.contains("SQLi") || finding.title.contains("SQL Injection") {
            Self::confirm_sql_injection(finding)
        } else if finding.title.contains("LFI") || finding.title.contains("File Inclusion") {
            Self::confirm_lfi(finding)
        } else if finding.title.contains("XSS") || finding.title.contains("Cross-Site") {
            Self::confirm_xss(finding)
        } else if finding.title.contains("CMDi") || finding.title.contains("Command Injection") {
            Self::confirm_cmdi(finding)
        } else if finding.title.contains("Admin") || finding.title.contains("Panel") {
            Self::confirm_admin_panel(finding)
        } else {
            matches!(finding.severity, crate::detection::analyzer::Severity::High | crate::detection::analyzer::Severity::Critical)
        }
    }

    fn confirm_sql_injection(finding: &Finding) -> bool {
        let evidence = finding.evidence.to_lowercase();
        // Require actual SQL error context, not just generic keywords
        let has_sql_error = evidence.contains("sql syntax") ||
            evidence.contains("unclosed quotation") ||
            (evidence.contains("ora-") && evidence.split("ora-").skip(1).any(|s| s.chars().next().map_or(false, |c| c.is_ascii_digit()))) ||
            evidence.contains("sqlstate") ||
            evidence.contains("incorrect syntax near") ||
            evidence.contains("column count") ||
            (evidence.contains("mysql_fetch") || evidence.contains("mysql_error") || evidence.contains("supplied argument is not a valid mysql"));
        has_sql_error &&
        !evidence.contains("cf-ray") &&
        !evidence.contains("cloudflare") &&
        !evidence.to_lowercase().contains("waf-block") && !evidence.to_lowercase().contains("waf-denied") &&
        !evidence.contains("blocked")
    }

    fn confirm_xss(finding: &Finding) -> bool {
        let evidence = finding.evidence.to_lowercase();
        // Require explicit XSS payload match, not generic HTML keywords
        let has_xss_payload = evidence.contains("<script>alert(") ||
            evidence.contains("<img src=x onerror=alert(") ||
            evidence.contains("javascript:alert(") ||
            evidence.contains("<svg onload=alert(");
        has_xss_payload &&
        !evidence.contains("&lt;") &&
        !evidence.contains("&gt;") &&
        !evidence.contains("&quot;")
    }

    fn confirm_cmdi(finding: &Finding) -> bool {
        let evidence = finding.evidence.to_lowercase();
        // Require at least 2 distinct indicators
        let mut hits = 0;
        if (evidence.contains("uid=") && evidence.contains("gid=") && evidence.contains("groups=")) || (evidence.contains("uid=") && evidence.contains("(")) { hits += 1; }
        if evidence.contains("/bin/bash") || evidence.contains("/bin/sh") { hits += 1; }
        if evidence.contains("permission denied") || evidence.contains("command not found") { hits += 1; }

        hits >= 2
    }

    fn confirm_lfi(finding: &Finding) -> bool {
        let evidence = finding.evidence.to_lowercase();
        if !evidence.contains("root:x:0:0") && !evidence.contains("daemon:x:") {
            return false;
        }
        let lines: Vec<&str> = evidence.lines().collect();
        lines.iter().any(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            parts.len() >= 6 && parts[2].parse::<u32>().is_ok() && parts[3].parse::<u32>().is_ok()
        })
    }

    fn confirm_admin_panel(finding: &Finding) -> bool {
        let url = finding.url.to_lowercase();
        (url.split('/').any(|p| p == "admin") || url.contains("/login") || url.contains("/dashboard")) &&
        !finding.evidence.is_empty() &&
        !finding.evidence.to_lowercase().contains("cf-ray") &&
        !finding.evidence.to_lowercase().contains("cloudflare")
    }

    pub fn reduce_false_positive(findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| Self::confirm_vulnerability(f))
            .collect()
    }
}

// ── BehaviorAnalyzer — HyperSecurity_Offensive_Labs / khaninkali ──────────────
// Real-world response profiling engine used by professional red teams to detect
// WAF appliances, fingerprint backend technologies via header/body signatures,
// and identify anomalous responses indicative of successful injection.
//
// Methods in this module are designed for offensive engagements — they feed
// directly into the scanner pipeline to reduce false positives and surface
// bypass opportunities that automated scanners typically miss.

pub struct BehaviorAnalyzer {
    waf_vendors: Vec<(&'static str, Vec<&'static str>)>,
}

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        let mut waf_vendors: Vec<(&'static str, Vec<&'static str>)> = Vec::new();

        waf_vendors.push(("Cloudflare", vec![
            "cf-ray", "__cfduid", "cf-cache-status", "cf-request-id",
            "cf-waf-error", "cloudflare", "cf-challenge",
        ]));
        waf_vendors.push(("AWS WAF", vec![
            "awselb", "x-amzn-requestid", "x-amz-cf-id",
            "x-amz-cf-pop", "x-amzn-ErrorType", "aws-waf-token",
        ]));
        waf_vendors.push(("ModSecurity", vec![
            "mod_security", "NOYB", "OWASP_CRS", "ModSecurity",
            "x-modsec", "x-owasp-crs",
        ]));
        waf_vendors.push(("F5 BIG-IP ASM", vec![
            "BigIP", "TSessionId", "MRHSHint",
            "MRHInt", "x-wa-ident",
        ]));
        waf_vendors.push(("Imperva Incapsula", vec![
            "incap_ses", "incap_vis", "Incapsula", "X-Iinfo",
            "imperva", "visid_incap",
        ]));
        waf_vendors.push(("Akamai", vec![
            "akamai", "ak_bmsc", "bm_sz", "akavpau",
            "abck", "akacd",
        ]));
        waf_vendors.push(("Sucuri", vec![
            "sucuri", "X-Sucuri-ID", "Sucuri-Cloudproxy",
        ]));
        waf_vendors.push(("Radware", vec![
            "radware", "X-RW-", "alteon",
        ]));
        waf_vendors.push(("Palo Alto", vec![
            "PAN-", "x-pan-", "global-protect",
        ]));
        waf_vendors.push(("Fortinet FortiWeb", vec![
            "FortiWeb", "FORTIWAF", "x-forti-",
        ]));
        waf_vendors.push(("Barracuda", vec![
            "barracuda", "x-barracuda-", "BarracudaWAF",
        ]));
        waf_vendors.push(("Citrix NetScaler", vec![
            "netscaler", "NS-CACHE", "Citrix",
        ]));

        Self {
            waf_vendors,
        }
    }

    pub fn detect_error_page(&self, body: &str) -> Option<String> {
        let patterns: Vec<(&str, Vec<&str>)> = vec![
            ("MySQL Error", vec!["You have an error in your SQL syntax", "MySQL server version", "Warning: mysql_", "mysqli_fetch"]),
            ("MSSQL Error", vec!["Microsoft OLE DB", "Unclosed quotation mark", "Incorrect syntax near", "SQLSTATE[23000]"]),
            ("PostgreSQL Error", vec!["pg_query", "PSQLException", "pg_connect", "Warning: pg_"]),
            ("Oracle Error", vec!["ORA-", "Warning: oci_", "OCIParse"]),
            ("Java Error", vec!["NullPointerException", "Stack trace:", "at java.", "ServletException"]),
            ("Python Error", vec!["Traceback (most recent call last)", "File \"", "SyntaxError:", "NameError:"]),
            (".NET Error", vec!["System.Data.", "System.Web.", "System.NullReference", "ASP.NET"]),
            ("PHP Error", vec!["PHP Fatal error", "PHP Warning", "PHP Notice", "Parse error"]),
            ("Ruby Error", vec!["NoMethodError", "NameError in", "ActionController"]),
            ("Express/Node Error", vec!["SyntaxError: Unexpected token", "Cannot find module", "TypeError: Cannot read property"]),
            ("Generic SQL", vec!["SQL syntax", "SQLSTATE", "syntax error at"]),
        ];

        for (tech, signatures) in &patterns {
            let match_count = signatures.iter().filter(|sig| body.contains(*sig)).count();
            if match_count >= 2 {
                return Some(tech.to_string());
            }
        }
        None
    }

    pub fn detect_waf(&self, headers: &[String]) -> Option<String> {
        let header_lower: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();

        for (name, sigs) in &self.waf_vendors {
            for sig in sigs {
                if header_lower.iter().any(|h| h.contains(&sig.to_lowercase())) {
                    return Some(name.to_string());
                }
            }
        }

        None
    }

    pub fn detect_tech_stack(&self, headers: &[String], body: &str) -> Vec<String> {
        let mut techs = Vec::new();
        let header_lower: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();

        let server_header = header_lower.iter().find(|h| h.starts_with("server:"));
        if let Some(s) = server_header {
            let val = s.trim_start_matches("server:").trim();
            if val.contains("nginx/") || val.contains("nginx ") { techs.push("Nginx".to_string()); }
            if val.contains("apache/") { techs.push("Apache".to_string()); }
            if val.to_lowercase().contains("microsoft-iis") || val.to_lowercase().contains("iis/") { techs.push("IIS".to_string()); }
            if val.contains("cloudflare") { techs.push("Cloudflare".to_string()); }
        }

        let powered_by = header_lower.iter().find(|h| h.starts_with("x-powered-by:"));
        if let Some(s) = powered_by {
            let val = s.trim_start_matches("x-powered-by:").trim();
            if val.contains("php/") { techs.push("PHP".to_string()); }
            if val.contains("ASP.NET") { techs.push("ASP.NET".to_string()); }
            if val.contains("express/") { techs.push("Express".to_string()); }
        }

        if body.contains("wp-content") || body.contains("wp-includes") {
            techs.push("WordPress".to_string());
        }
        if body.contains("Joomla!") || body.contains("com_content") {
            techs.push("Joomla".to_string());
        }
        if body.contains("Drupal ") || body.contains("Drupal/") || body.contains("\"Drupal\"") || body.contains("drupal.js") {
            techs.push("Drupal".to_string());
        }
        if body.contains("Shopify ") || body.contains("Shopify/") || body.contains("\"Shopify\"") || body.contains("myshopify.com") {
            techs.push("Shopify".to_string());
        }
        if body.contains("Laravel ") || body.contains("Laravel/") || body.contains("\"Laravel\"") || body.contains("laravel_session") {
            techs.push("Laravel".to_string());
        }
        if body.contains("csrfmiddlewaretoken") || ((body.contains("Django ") || body.contains("Django/") || body.contains("\"Django\"")) && body.contains("__admin")) {
            techs.push("Django".to_string());
        }
        if body.contains("Ruby on Rails") && body.contains("csrf-token") {
            techs.push("Rails".to_string());
        }

        techs.sort();
        techs.dedup();
        techs
    }

}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for BehaviorAnalyzer {
    fn clone(&self) -> Self {
        Self {
            waf_vendors: self.waf_vendors.clone(),
        }
    }
}

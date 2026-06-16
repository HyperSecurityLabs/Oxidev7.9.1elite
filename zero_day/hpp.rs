use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use colored::Colorize;
use url::Url;

use crate::cli::display::{
    COL_MED, ELITE_CYAN, ELITE_JADE_B, ELITE_LAVENDER, ELITE_LAVENDER_B,
};
use crate::detection::analyzer::{Finding, Severity};
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;

fn tc(s: &str, c: (u8, u8, u8)) -> String {
    s.truecolor(c.0, c.1, c.2).to_string()
}

const HPP_PAYLOADS: &[(&str, &str)] = &[
    ("dup-int",   "42"),
    ("dup-str",   "hpp_test"),
    ("dup-empty", ""),
    ("dup-sql",   "' OR '1'='1"),
    ("dup-xss",   "<script>"),
    ("dup-special", "!@#$%^&*()"),
    ("dup-json",  "{\"a\":1}"),
    ("dup-array", "[]"),
];

pub struct HppDetector;

impl HppDetector {
    pub async fn scan(client: &Arc<HttpClient>, urls: &[String], findings: &mut Vec<Finding>) -> Result<HppSummary> {
        let mut summary = HppSummary::default();
        let candidates: Vec<&String> = urls.iter().filter(|u| has_query_params(u)).collect();

        if candidates.is_empty() {
            println!("  {} No URLs with query parameters found — skipping HPP scan",
                tc("!", COL_MED));
            return Ok(summary);
        }

        println!("  {} HTTP Parameter Pollution scan: {} URL candidates",
            tc("▸", ELITE_CYAN),
            tc(&candidates.len().to_string(), ELITE_LAVENDER_B));

        for (idx, url) in candidates.iter().enumerate() {
            if crate::is_shutdown_requested() {
                break;
            }

            let base_req = HttpRequest::get(url);
            let base_resp = match tokio::time::timeout(Duration::from_secs(8), client.send(base_req)).await {
                Ok(Ok(r)) => r,
                _ => continue,
            };
            let base_len = base_resp.body.len();

            let parsed = match Url::parse(url) {
                Ok(u) => u,
                Err(_) => continue,
            };
            let params: Vec<(String, String)> = parsed.query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();

            if params.is_empty() {
                continue;
            }

            let mut vulnerable_params = Vec::new();

            for (param_name, original_val) in &params {
                for (variant_label, poison_val) in HPP_PAYLOADS {
                    let hpp_url = build_hpp_url(url, param_name, original_val, poison_val);
                    let req = HttpRequest::get(&hpp_url);

                    match tokio::time::timeout(Duration::from_secs(8), client.send(req)).await {
                        Ok(Ok(resp)) => {
                            summary.total_requests += 1;
                            let delta = (resp.body.len() as i64 - base_len as i64).unsigned_abs();
                            let significant = delta > 256 || resp.status != base_resp.status;

                            if significant {
                                summary.total_anomalies += 1;
                                vulnerable_params.push((
                                    param_name.clone(),
                                    variant_label.to_string(),
                                    resp.status,
                                    delta,
                                ));
                            }
                        }
                        _ => {
                            summary.timeouts += 1;
                        }
                    }
                }
            }

            if !vulnerable_params.is_empty() {
                summary.vulnerable_count += 1;
                let details: Vec<String> = vulnerable_params.iter()
                    .map(|(p, v, status, delta)| {
                        format!("{} via {} | status={} | Δbody={}B", p, v, status, delta)
                    })
                    .collect();

                let finding = Finding::new(
                    url,
                    Severity::High,
                    "[HPP] HTTP Parameter Pollution",
                    &format!(
                        "Parameter pollution detected on {} parameter(s). \
                         Server behaviour changes when duplicate parameters are sent. \
                         {}",
                        vulnerable_params.len(),
                        details.join("; "),
                    ),
                )
                .with_evidence(&format!("Parameters affected: {}",
                    vulnerable_params.iter().map(|(p, _, _, _)| p.as_str()).collect::<Vec<_>>().join(", ")))
                .with_remediation(
                    "Reject requests with duplicate parameters. \
                     Use the last-occurring value consistently. \
                     Implement input validation on server-side."
                );

                findings.push(finding);
                println!("  {} [HPP] {} — {} parameter(s) vulnerable",
                    tc("⚠", COL_MED),
                    tc(&truncate_url(url, 60), ELITE_LAVENDER),
                    tc(&vulnerable_params.len().to_string(), COL_MED));
            }

            if idx % 5 == 0 {
                print!("\r  {} Progress: {}/{} URLs  |  anomalies: {}  |  vuln URLs: {}   ",
                    tc("▸", ELITE_CYAN),
                    tc(&(idx + 1).to_string(), ELITE_JADE_B),
                    tc(&candidates.len().to_string(), ELITE_LAVENDER_B),
                    tc(&summary.total_anomalies.to_string(), COL_MED),
                    tc(&summary.vulnerable_count.to_string(), COL_MED));
                use std::io::{Write, stdout};
                stdout().flush().ok();
            }
        }

        println!();
        println!("  {} HPP scan complete — {} vulnerable URLs, {} anomalies, {} timeouts",
            tc("✓", ELITE_JADE_B),
            tc(&summary.vulnerable_count.to_string(), COL_MED),
            tc(&summary.total_anomalies.to_string(), COL_MED),
            tc(&summary.timeouts.to_string(), ELITE_LAVENDER_B));

        Ok(summary)
    }
}

fn has_query_params(url: &str) -> bool {
    url.contains('?')
}

fn build_hpp_url(base_url: &str, param: &str, _orig_val: &str, poison: &str) -> String {
    let fragment_stripped = match base_url.find('#') {
        Some(pos) => &base_url[..pos],
        None => base_url,
    };
    format!("{}&{}={}", fragment_stripped, param, poison)
}

fn truncate_url(url: &str, max: usize) -> String {
    if url.len() > max {
        format!("...{}", &url[url.len().saturating_sub(max - 3)..])
    } else {
        url.to_string()
    }
}

#[derive(Default, Debug)]
pub struct HppSummary {
    pub vulnerable_count: usize,
    pub total_anomalies: usize,
    pub total_requests: usize,
    pub timeouts: usize,
}

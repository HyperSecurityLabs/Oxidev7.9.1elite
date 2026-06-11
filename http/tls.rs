pub fn check_tls_version(url: &str) -> String {
    if url.starts_with("https://") {
        "TLS detected".to_string()
    } else {
        "No TLS".to_string()
    }
}

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub threads: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub insecure: bool,
    pub rate_limit: Option<u64>,
    pub modules: Vec<String>,
    pub headers: HashMap<String, String>,

    pub timeout: Option<u64>,
    pub payload_limit: Option<usize>,
    pub exploitation_level: Option<u8>,
    pub proxy: Option<String>,
    pub cookie: Option<String>,
    pub silent_mode: Option<bool>,
    pub format: Option<String>,
    pub output: Option<String>,
    pub crawl_depth: Option<u8>,
    pub max_urls: Option<usize>,
    pub download: Option<bool>,
    pub exclude: Option<Vec<String>>,
    pub zeroday: Option<bool>,
    pub active: Option<bool>,
    pub train: Option<bool>,
    pub insta: Option<bool>,
    pub session: Option<bool>,
    pub multiattack: Option<bool>,
    pub duration: Option<u64>,
    pub jobs: Option<usize>,
    pub headless: Option<bool>,
    pub resume: Option<bool>,
    pub verbose: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: 20,
            user_agent: "OXIDE/1.0.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            insecure: false,
            rate_limit: None,
            modules: vec!["all".to_string()],
            headers: HashMap::new(),

            timeout: None,
            payload_limit: None,
            exploitation_level: None,
            proxy: None,
            cookie: None,
            silent_mode: None,
            format: None,
            output: None,
            crawl_depth: None,
            max_urls: None,
            download: None,
            exclude: None,
            zeroday: None,
            active: None,
            train: None,
            insta: None,
            session: None,
            multiattack: None,
            duration: None,
            jobs: None,
            headless: None,
            resume: None,
            verbose: None,
        }
    }
}

impl Config {
    pub fn generate() -> Self {
        let uas = [
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/604.1",
        ];

        Self {
            threads: 8 + (rand::random::<u32>() % 17) as usize,
            user_agent: uas[rand::random::<u32>() as usize % uas.len()].to_string(),
            follow_redirects: true,
            max_redirects: 10,
            insecure: false,
            rate_limit: None,
            modules: vec!["all".to_string()],
            headers: HashMap::new(),
            timeout: Some(15 + (rand::random::<u32>() % 31) as u64),
            payload_limit: Some(50),
            exploitation_level: Some(30 + (rand::random::<u32>() % 41) as u8),
            proxy: None,
            cookie: None,
            silent_mode: None,
            format: None,
            output: None,
            crawl_depth: Some(2 + (rand::random::<u32>() % 4) as u8),
            max_urls: Some(100),
            download: None,
            exclude: None,
            zeroday: None,
            active: None,
            train: None,
            insta: None,
            session: None,
            multiattack: None,
            duration: None,
            jobs: Some(1 + (rand::random::<u32>() % 4) as usize),
            headless: None,
            resume: None,
            verbose: None,
        }
    }

    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;

        Ok(config)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize config")?;

        fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }

    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    pub fn get_headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
}

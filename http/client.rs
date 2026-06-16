use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder, cookie::Jar, redirect::Policy};
use std::sync::Arc;
use super::request::HttpRequest;
use super::response::HttpResponse;
use super::useragents::UserAgentPool;

#[derive(Clone)]
pub struct HttpClientConfig {
    pub insecure: bool,
    pub proxy: Option<String>,
    pub user_agent: Option<String>,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub cookie: Option<String>,
    pub jobs: usize,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            insecure: false,
            proxy: None,
            user_agent: None,
            follow_redirects: true,
            max_redirects: 10,
            cookie: None,
            jobs: 2,
        }
    }
}

#[derive(Clone)]
pub struct HttpClient {
    client:     Client,
    ua_pool:    UserAgentPool,
    user_agent: Option<String>,
    cookie_str: Option<String>,
}

impl HttpClient {
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        let client = Self::build_client(&config)?;
        Ok(Self {
            client,
            ua_pool:  UserAgentPool::full(),
            user_agent: config.user_agent,
            cookie_str: config.cookie,
        })
    }

    fn build_client(config: &HttpClientConfig) -> Result<Client> {
        let mut builder = ClientBuilder::new()
            .danger_accept_invalid_certs(config.insecure)
            .timeout(std::time::Duration::from_secs(30))
            .cookie_store(true)
            .pool_max_idle_per_host(config.jobs.max(8))
            .tcp_keepalive(std::time::Duration::from_secs(30));

        if let Some(ref cookie_str) = config.cookie {
            let jar = Jar::default();
            for pair in cookie_str.split(';') {
                let parts: Vec<&str> = pair.splitn(2, '=').collect();
                if parts.len() == 2 {
                    jar.add_cookie_str(
                        &format!("{}={}", parts[0].trim(), parts[1].trim()),
                        &"http://localhost".parse().unwrap(),
                    );
                }
            }
            builder = builder.cookie_provider(Arc::new(jar));
        }

        if let Some(ref proxy_url) = config.proxy {
            let parsed = reqwest::Proxy::all(proxy_url)
                .with_context(|| format!("Invalid proxy URL: {}", proxy_url))?;
            builder = builder.proxy(parsed);
        }

        builder = builder.redirect(Policy::limited(config.max_redirects as usize));

        builder
            .build()
            .with_context(|| "Failed to build HTTP client")
    }

    pub fn cookie_string(&self) -> Option<&str> {
        self.cookie_str.as_deref()
    }

    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
        let ua = self.user_agent.as_deref().unwrap_or_else(|| self.ua_pool.next());
        let (accept, accept_lang, accept_enc) = UserAgentPool::accept_headers_for(ua);

        let mut req = self.client.request(request.method.clone(), request.url.as_str());

        // Apply custom headers from request first, then override critical headers
        // with pool-selected values so UA rotation works correctly.
        for (key, value) in &request.headers {
            let key_lower = key.to_lowercase();
            match key_lower.as_str() {
                "user-agent" | "accept" | "accept-language" | "accept-encoding" => {}
                _ => { req = req.header(key, value); }
            }
        }

        req = req
            .header("User-Agent",      ua)
            .header("Accept",          accept)
            .header("Accept-Language", accept_lang)
            .header("Accept-Encoding", accept_enc);

        if let Some(body) = &request.body {
            req = req.body(body.clone());
        }
        let response = req
            .send()
            .await
            .with_context(|| format!("Failed to send request to {}", request.url))?;
        HttpResponse::from_reqwest(response).await
    }

    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.send(HttpRequest::get(url)).await
    }

    pub async fn post(&self, url: &str, body: &str) -> Result<HttpResponse> {
        self.send(HttpRequest::post(url, body)).await
    }
}

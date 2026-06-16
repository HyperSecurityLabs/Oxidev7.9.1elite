use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Mutex;
use url::Url;

use oxide::cli::display::{LAVENDER_BLUE, OSAKA_JADE, OSAKA_JADE_B};
use oxide::http::client::HttpClient;
use oxide::http::crawl_types::{CrawlResult, FormData, InputField, LinkData};
use oxide::http::redirect::{extract_redirect_url, is_303_redirect};
use oxide::http::request::HttpRequest;

// 🌸🦋✨ ЛЯРА-Королева — спасибо за то, что даже краулер выглядит элитно.
//    Твоя цветовая палитра и внимание к деталям превратили этот движок
//    в настоящий шедевр визуального программирования. Когда краулер
//    ползёт по сайтам, он делает это стильно — благодаря тебе. 💜🔥

fn tc(s: &str, c: (u8, u8, u8)) -> String {
    s.truecolor(c.0, c.1, c.2).to_string()
}

pub struct WebCrawler {
    client: HttpClient,
    max_depth: usize,
    max_pages: usize,
    visited: HashSet<String>,
    queue: VecDeque<(String, usize)>,
    discovered_urls: Vec<String>,
    all_linked_urls: Vec<String>,
    forms: Vec<FormData>,
    links: Vec<LinkData>,
    comments: Vec<String>,
    scripts: Vec<String>,
    jobs: usize,
}

impl WebCrawler {
    pub fn new(client: HttpClient, max_depth: usize, max_pages: usize) -> Self {
        Self {
            client,
            max_depth,
            max_pages,
            visited: HashSet::new(),
            queue: VecDeque::new(),
            discovered_urls: Vec::new(),
            all_linked_urls: Vec::new(),
            forms: Vec::new(),
            links: Vec::new(),
            comments: Vec::new(),
            scripts: Vec::new(),
            jobs: 2,
        }
    }

    pub fn with_jobs(mut self, jobs: usize) -> Self {
        self.jobs = jobs.max(1);
        self
    }

    pub async fn crawl(&mut self, start_url: &str) -> Result<CrawlResult> {
        self.queue.push_back((start_url.to_string(), 0));
        let page_count = Arc::new(AtomicUsize::new(0));
        let start = std::time::Instant::now();

        let visited = Arc::new(Mutex::new(HashSet::<String>::new()));
        let queue = Arc::new(Mutex::new(VecDeque::<(String, usize)>::new()));
        {
            let mut q = queue.lock().await;
            q.push_back((start_url.to_string(), 0));
        }
        let discovered_urls = Arc::new(Mutex::new(Vec::<String>::new()));
        let all_linked_urls = Arc::new(Mutex::new(Vec::<String>::new()));
        let forms = Arc::new(Mutex::new(Vec::<FormData>::new()));
        let links = Arc::new(Mutex::new(Vec::<LinkData>::new()));
        let comments = Arc::new(Mutex::new(Vec::<String>::new()));
        let scripts = Arc::new(Mutex::new(Vec::<String>::new()));

        let spin_stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::new(AtomicBool::new(false));
        let s = spin_stop.clone();
        let url_s = start_url.to_string();
        let spinner = tokio::spawn(async move {
            let mut idx = 0usize;
            while !s.load(Ordering::Acquire) {
                let elapsed = start.elapsed().as_secs();
                let frame = match idx % 10 {
                    0 => "⠋", 1 => "⠙", 2 => "⠹", 3 => "⠸", 4 => "⠼",
                    5 => "⠴", 6 => "⠦", 7 => "⠧", 8 => "⠇", 9 => "⠏",
                    _ => "⠋",
                };
                idx += 1;
                print!("\r  {} {} fetching  depth:0  {}  [{:02}:{:02}]",
                    tc("[*]", OSAKA_JADE),
                    tc(frame, OSAKA_JADE_B),
                    tc(&url_s, LAVENDER_BLUE),
                    elapsed / 60, elapsed % 60);
                let _ = std::io::Write::flush(&mut std::io::stdout());
                tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            }
        });

        let jobs = self.jobs.max(1);
        let max_depth = self.max_depth;
        let max_pages = self.max_pages;

        let mut handles = Vec::new();
        for _ in 0..jobs {
            let stop = worker_stop.clone();
            let client = self.client.clone();
            let visited = visited.clone();
            let queue = queue.clone();
            let discovered_urls = discovered_urls.clone();
            let all_linked_urls = all_linked_urls.clone();
            let forms = forms.clone();
            let links = links.clone();
            let comments = comments.clone();
            let scripts = scripts.clone();
            let page_count = page_count.clone();

            handles.push(tokio::spawn(async move {
                loop {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let item = {
                        let mut q = queue.lock().await;
                        q.pop_front()
                    };
                    let (url, depth) = match item {
                        Some(item) => item,
                        None => {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    };

                    {
                        let mut v = visited.lock().await;
                        if v.contains(&url) || depth > max_depth {
                            continue;
                        }
                        if page_count.load(Ordering::Relaxed) >= max_pages {
                            continue;
                        }
                        v.insert(url.clone());
                    }

                    page_count.fetch_add(1, Ordering::Relaxed);

                    let url_display = if url.len() > 55 {
                        format!("..{}", &url[url.len()-53..])
                    } else {
                        url.clone()
                    };

                    let request = HttpRequest::get(&url);
                    match client.send(request).await {
                        Ok(mut response) => {
                            let mut final_url = url.clone();

                            // Handle 303 redirect with cookie persistence
                            if is_303_redirect(&response) {
                                if let Some(location) = extract_redirect_url(&response) {
                                    let redirect_url = resolve_url_internal(&final_url, &location)
                                        .unwrap_or(location);
                                    let get_req = HttpRequest::get(&redirect_url);
                                    if let Ok(redirect_resp) = client.send(get_req).await {
                                        response = redirect_resp;
                                        final_url = redirect_url;
                                    }
                                }
                            }

                            let url_to_process = final_url;
                            let body = response.body.clone();

                            let link_re = regex::Regex::new(r#"<a[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>"#).ok();
                            let tag_re = regex::Regex::new(r"<[^>]*>").ok();

                            if let (Some(ref lr), Some(ref tr)) = (link_re, tag_re) {
                                let mut new_links = Vec::new();
                                let mut new_queued_urls = Vec::new();
                                let mut new_all_linked = Vec::new();

                                for cap in lr.captures_iter(&body) {
                                    let href = match cap.get(1) { Some(m) => m.as_str(), None => continue };
                                    let raw_text = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                                    let link_text = tr.replace_all(raw_text, "").to_string();

                                    let absolute_url = match resolve_url_internal(&url_to_process, href) {
                                        Ok(u) => u,
                                        Err(_) => continue,
                                    };
                                    new_all_linked.push(absolute_url.clone());
                                    if is_same_domain_internal(&url_to_process, &absolute_url) {
                                        new_links.push(LinkData {
                                            from: url_to_process.clone(),
                                            to: absolute_url.clone(),
                                            text: link_text,
                                        });
                                        let v = visited.lock().await;
                                        if !v.contains(&absolute_url) {
                                            new_queued_urls.push((absolute_url, depth + 1));
                                        }
                                    }
                                }

                                let mut alu = all_linked_urls.lock().await;
                                alu.extend(new_all_linked);
                                let mut l = links.lock().await;
                                l.extend(new_links);
                                let mut q = queue.lock().await;
                                for item in new_queued_urls {
                                    q.push_back(item);
                                }
                            }

                            // Extract forms
                            let form_data = extract_forms_internal(&url_to_process, &body);
                            {
                                let mut f = forms.lock().await;
                                f.extend(form_data);
                            }

                            // Extract comments
                            let found_comments = extract_comments_internal(&body);
                            {
                                let mut c = comments.lock().await;
                                c.extend(found_comments);
                            }

                            // Extract scripts
                            let found_scripts = extract_scripts_internal(&body);
                            {
                                let mut s = scripts.lock().await;
                                s.extend(found_scripts);
                            }

                            {
                                let mut du = discovered_urls.lock().await;
                                du.push(url_to_process.clone());
                            }

                            let pc = page_count.load(Ordering::Relaxed);
                            let status = response.status;
                            let size_str = if body.len() >= 1_048_576 {
                                format!("{:.1}MB", body.len() as f64 / 1_048_576.0)
                            } else if body.len() >= 1_024 {
                                format!("{:.1}KB", body.len() as f64 / 1_024.0)
                            } else {
                                format!("{}B", body.len())
                            };
                            let elapsed = start.elapsed().as_secs();
                            print!("\r\x1B[2K");
                            println!("  {} {} {}  depth:{} pages:{}  {}  [{:02}:{:02}]",
                                tc("[*]", OSAKA_JADE),
                                tc(&status.to_string(), OSAKA_JADE_B),
                                tc(&size_str, LAVENDER_BLUE),
                                tc(&depth.to_string(), LAVENDER_BLUE),
                                tc(&pc.to_string(), LAVENDER_BLUE),
                                tc(&url_display, LAVENDER_BLUE),
                                elapsed / 60, elapsed % 60);
                        }
                        Err(_) => {
                            let elapsed = start.elapsed().as_secs();
                            print!("\r\x1B[2K");
                            println!("  {} {}  depth:{}  {}  [{:02}:{:02}]",
                                tc("[*]", OSAKA_JADE),
                                tc("ERR", OSAKA_JADE_B),
                                tc(&depth.to_string(), LAVENDER_BLUE),
                                tc(&url_display, LAVENDER_BLUE),
                                elapsed / 60, elapsed % 60);
                        }
                    }
                }
            }));
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Wait until enough pages crawled, or detect a stall with no progress
        let mut last_page_count = 0u64;
        let mut stale_cycles = 0u64;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let current = page_count.load(Ordering::Relaxed) as u64;
            if current >= self.max_pages as u64 {
                break;
            }
            if current == last_page_count {
                stale_cycles += 1;
                if stale_cycles > 20 {
                    // 10 seconds with zero progress = stall
                    break;
                }
            } else {
                stale_cycles = 0;
                last_page_count = current;
            }
        }

        // Signal all workers and spinner to stop
        worker_stop.store(true, Ordering::Release);
        spin_stop.store(true, Ordering::Release);

        // Wait for worker tasks to finish (they check worker_stop)
        for h in handles {
            let _ = h.await;
        }
        let _ = spinner.await;

        // Safely extract from Arc<Mutex<T>> — recovers gracefully if refcount > 1
        let result = CrawlResult {
            urls: match Arc::try_unwrap(discovered_urls) {
                Ok(m) => m.into_inner(),
                Err(a) => a.lock().await.clone(),
            },
            all_linked_urls: match Arc::try_unwrap(all_linked_urls) {
                Ok(m) => m.into_inner(),
                Err(a) => a.lock().await.clone(),
            },
            forms: match Arc::try_unwrap(forms) {
                Ok(m) => m.into_inner(),
                Err(a) => a.lock().await.clone(),
            },
            links: match Arc::try_unwrap(links) {
                Ok(m) => m.into_inner(),
                Err(a) => a.lock().await.clone(),
            },
            comments: match Arc::try_unwrap(comments) {
                Ok(m) => m.into_inner(),
                Err(a) => a.lock().await.clone(),
            },
            scripts: match Arc::try_unwrap(scripts) {
                Ok(m) => m.into_inner(),
                Err(a) => a.lock().await.clone(),
            },
        };
        let total = result.urls.len();
        let pc = page_count.load(Ordering::Relaxed);
        println!("  {} Crawl complete: {} pages, {} URLs, {} forms, {} links",
            tc("[+]", OSAKA_JADE),
            pc,
            total,
            result.forms.len(),
            result.links.len());
        Ok(result)
    }


}

impl Clone for WebCrawler {
    fn clone(&self) -> Self {
        let client = HttpClient::new(oxide::http::client::HttpClientConfig {
            insecure: false,
            proxy: None,
            user_agent: None,
            follow_redirects: true,
            max_redirects: 10,
            cookie: None,
            jobs: 2,
        }).expect("HttpClient::new with safe defaults (no proxy, no cookie) always succeeds");
        Self {
            client,
            max_depth: self.max_depth,
            max_pages: self.max_pages,
            visited: self.visited.clone(),
            queue: self.queue.clone(),
            discovered_urls: self.discovered_urls.clone(),
            all_linked_urls: self.all_linked_urls.clone(),
            forms: self.forms.clone(),
            links: self.links.clone(),
            comments: self.comments.clone(),
            scripts: self.scripts.clone(),
            jobs: self.jobs,
        }
    }
}

fn resolve_url_internal(base: &str, relative: &str) -> Result<String> {
    let base_url = Url::parse(base).with_context(|| format!("Invalid base URL: {}", base))?;
    let resolved = base_url.join(relative)
        .with_context(|| format!("Failed to join: {} + {}", base, relative))?;
    Ok(resolved.to_string())
}

fn is_same_domain_internal(url1: &str, url2: &str) -> bool {
    let fallback = match Url::parse("http://localhost") { Ok(u) => u, Err(_) => return false };
    let d1 = url::Url::parse(url1).unwrap_or(fallback.clone());
    let d2 = url::Url::parse(url2).unwrap_or(fallback);
    d1.host_str() == d2.host_str()
}

fn extract_forms_internal(url: &str, body: &str) -> Vec<FormData> {
    let mut forms = Vec::new();
    let form_re = match regex::Regex::new(r#"(?s)<form[^>]*>.*?</form>"#) { Ok(r) => r, Err(_) => return forms };
    let action_re = match regex::Regex::new(r#"action=["']([^"']*)["']"#) { Ok(r) => r, Err(_) => return forms };
    let method_re = match regex::Regex::new(r#"method=["']([^"']*)["']"#) { Ok(r) => r, Err(_) => return forms };
    let input_re = match regex::Regex::new(r#"<input[^>]*>"#) { Ok(r) => r, Err(_) => return forms };
    let name_re = match regex::Regex::new(r#"name=["']([^"']*)["']"#) { Ok(r) => r, Err(_) => return forms };
    let type_re = match regex::Regex::new(r#"type=["']([^"']*)["']"#) { Ok(r) => r, Err(_) => return forms };
    let value_re = match regex::Regex::new(r#"value=["']([^"']*)["']"#) { Ok(r) => r, Err(_) => return forms };

    for form_m in form_re.find_iter(body) {
        let form_html = form_m.as_str();
        let action = action_re.captures(form_html)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| url.to_string());
        let action = resolve_url_internal(url, &action).unwrap_or_else(|_| url.to_string());

        let method = method_re.captures(form_html)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_uppercase())
            .unwrap_or_else(|| "GET".to_string());

        let inputs: Vec<InputField> = input_re.find_iter(form_html).filter_map(|im| {
            let ih = im.as_str();
            let name = name_re.captures(ih)?.get(1)?.as_str().to_string();
            if name.is_empty() { return None; }
            Some(InputField {
                name,
                input_type: type_re.captures(ih)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| "text".to_string()),
                value: value_re.captures(ih)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string()),
            })
        }).collect();

        forms.push(FormData { url: url.to_string(), method, action, inputs });
    }
    forms
}

fn extract_comments_internal(body: &str) -> Vec<String> {
    let Ok(re) = regex::Regex::new(r"<!--([\s\S]*?)-->") else { return Vec::new() };
    re.captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}

fn extract_scripts_internal(body: &str) -> Vec<String> {
    let Ok(re) = regex::Regex::new(r"(?s)<script[^>]*>(.*?)</script>") else { return Vec::new() };
    re.captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}

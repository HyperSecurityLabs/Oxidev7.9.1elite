#[derive(Clone, Debug)]
pub struct FormData {
    pub url: String,
    pub method: String,
    pub action: String,
    pub inputs: Vec<InputField>,
}

#[derive(Clone, Debug)]
pub struct InputField {
    pub name: String,
    pub input_type: String,
    pub value: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LinkData {
    pub from: String,
    pub to: String,
    pub text: String,
}

#[derive(Debug)]
pub struct CrawlResult {
    pub urls: Vec<String>,
    pub all_linked_urls: Vec<String>,
    pub forms: Vec<FormData>,
    pub links: Vec<LinkData>,
    pub comments: Vec<String>,
    pub scripts: Vec<String>,
}

impl CrawlResult {
    pub fn get_forms_by_method(&self, method: &str) -> Vec<&FormData> {
        self.forms.iter().filter(|f| f.method.eq_ignore_ascii_case(method)).collect()
    }

    pub fn get_all_link_texts(&self) -> Vec<&String> {
        self.links.iter().map(|l| &l.text).filter(|t| !t.is_empty()).collect()
    }

    pub fn suspicious_comments(&self) -> Vec<(&String, &'static str)> {
        let patterns: &[(&str, &str)] = &[
            ("password", "possible credential"),
            ("passwd",   "possible credential"),
            ("secret",   "possible secret"),
            ("token",    "possible token"),
            ("api_key",  "possible API key"),
            ("todo",     "developer note"),
            ("fixme",    "developer note"),
            ("hack",     "developer note"),
            ("/etc/",    "internal path"),
            ("192.168.", "internal IP"),
            ("10.0.",    "internal IP"),
        ];
        self.comments.iter().filter_map(|c| {
            let cl = c.to_lowercase();
            patterns.iter().find(|(p, _)| cl.contains(p)).map(|(_, reason)| (c, *reason))
        }).collect()
    }

    pub fn script_endpoints(&self) -> Vec<String> {
        let Ok(re) = regex::Regex::new(r#"["'](/(?:api|v\d|rest|graphql)[^"'\s]*)"#) else {
            return Vec::new();
        };
        self.scripts.iter().flat_map(|s| {
            re.captures_iter(s)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        }).collect()
    }
}

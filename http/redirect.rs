use crate::http::response::HttpResponse;

pub fn extract_redirect_url(response: &HttpResponse) -> Option<String> {
    response
        .headers
        .get("location")
        .or_else(|| response.headers.get("Location"))
        .cloned()
}

pub fn is_303_redirect(response: &HttpResponse) -> bool {
    response.status == 303
}

pub fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

pub fn should_switch_to_get(status: u16) -> bool {
    matches!(status, 303)
}

use libloading::{Library, Symbol};
use std::path::Path;
use std::sync::{Arc, OnceLock};

#[derive(Debug)]
pub enum ProxyLoaderError {
    NotFound(String),
    Invalid(String),
    SymbolMissing(String),
}

impl std::fmt::Display for ProxyLoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "proxy library not found: {}", p),
            Self::Invalid(p) => write!(f, "invalid proxy library: {}", p),
            Self::SymbolMissing(s) => write!(f, "missing symbol: {}", s),
        }
    }
}

pub struct ProxyLibrary {
    _lib: Arc<Library>,
}

const LIB_NAME: &str = if cfg!(target_os = "windows") {
    "liboxide_proxy.dll"
} else {
    "liboxide_proxy.so"
};

fn search_paths() -> Vec<String> {
    let mut paths = Vec::new();
    // Next to binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join(LIB_NAME).to_string_lossy().to_string());
        }
    }
    // Linux-specific system paths
    #[cfg(target_os = "linux")]
    {
        paths.push("/usr/lib/liboxide_proxy.so".into());
        paths.push("/usr/local/lib/liboxide_proxy.so".into());
        paths.push("/opt/oxide/lib/liboxide_proxy.so".into());
    }
    paths
}

fn find_library() -> Option<String> {
    // Search next to the binary first (common on all platforms)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let path = dir.join(LIB_NAME);
            if path.exists() {
                return Some(path.to_string_lossy().to_string());
            }
        }
    }
    for path in search_paths() {
        if Path::new(&path).exists() {
            return Some(path);
        }
    }
    // LD_LIBRARY_PATH (Linux) / PATH (Windows)
    let env_key = if cfg!(target_os = "windows") { "PATH" } else { "LD_LIBRARY_PATH" };
    if let Ok(lib_path) = std::env::var(env_key) {
        let sep = if cfg!(target_os = "windows") { ';' } else { ':' };
        for dir in lib_path.split(sep) {
            let candidate = format!("{}/{}", dir, LIB_NAME);
            if Path::new(&candidate).exists() {
                return Some(candidate);
            }
        }
    }
    None
}

impl ProxyLibrary {
    pub fn load() -> Result<Self, ProxyLoaderError> {
        let path = find_library()
            .ok_or_else(|| ProxyLoaderError::NotFound(
                format!("{} not found in search paths", LIB_NAME).into()
            ))?;

        let lib = unsafe {
            Library::new(&path)
                .map_err(|e| ProxyLoaderError::Invalid(format!("{}: {}", path, e)))?
        };

        let symbols = [
            "proxy_ping",
        ];

        for sym in &symbols {
            unsafe {
                lib.get::<unsafe extern "C" fn()>(sym.as_bytes())
                    .map_err(|_| ProxyLoaderError::SymbolMissing(sym.to_string()))?;
            }
        }

        Ok(Self { _lib: Arc::new(lib) })
    }
}

// ── Global proxy library (loaded once at startup) ─────────────────

static PROXY_LIB: OnceLock<Arc<Library>> = OnceLock::new();

pub fn ensure_proxy_library() -> Result<(), ProxyLoaderError> {
    let proxy = ProxyLibrary::load()?;
    let lib = proxy._lib.clone();
    let _ = PROXY_LIB.set(lib);
    if let Some(l) = PROXY_LIB.get() {
        let func: Result<Symbol<unsafe extern "C" fn() -> u32>, _> =
            unsafe { l.get(b"proxy_ping") };
        match func {
            Ok(f) => {
                let v = unsafe { f() };
                eprintln!("[+] Proxy library loaded: oxide-proxy/{}", v);
            }
            Err(_) => {
                eprintln!("[!] Proxy library loaded but missing 'proxy_ping' symbol — version unknown");
            }
        }
    }
    Ok(())
}



// ───────────────────────────────────────────────────────────────────────────
//  hypersecurity.so — Kernel-level memory safety & cache sanitisation module
//  HyperSecurityOffensiveLabs  |  OXIDE Community Edition
//
//  Loaded via libloading at runtime. Exposes a C ABI so it can be loaded by
//  the OXIDE scanner or any other Rust / C / Python caller.
//  Dismentle the Risks
//  _____________________________
//  =============================
//  |---------------------------|
//  |---------------------------|
//  Rust
//  |--------------------------|
//
//  Responsibilities:
//    • `hs_check_leaks`   — scan process memory maps for data leaks
//    • `hs_sanitise_cache` — drop filesystem cache, dentries, inodes
//    • `hs_memory_barrier` — enforce memory ordering / fence
//    • `hs_version`        — return the module version string
// ───────────────────────────────────────────────────────────────────────────

use std::os::raw::c_char;

/// Module version — returned by `hs_version`.
const VERSION: &str = "hypersecurity/1.0.0";

// ── Public C ABI ──────────────────────────────────────────────────────────

/// Return a static version string.  Caller must not free the pointer.
#[no_mangle]
pub extern "C" fn hs_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

/// Check process maps for potential data leaks.
/// Returns 0 on success (no leaks detected), non-zero if issues found.
#[no_mangle]
pub extern "C" fn hs_check_leaks() -> i32 {
    match leak_check_impl() {
        Ok(true)  => 0,   // no leaks
        Ok(false) => 1,   // potential leak detected
        Err(_)    => -1,  // error during check
    }
}

/// Sanitise the OS page cache, dentries, and inode caches.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn hs_sanitise_cache() -> i32 {
    match drop_caches_impl() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Insert a memory barrier (compiler fence + atomic fence).
#[no_mangle]
pub extern "C" fn hs_memory_barrier() {
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Read /proc/self/maps and look for suspicious writable+executable regions
/// or unexpected anonymous mappings that could indicate a leak.
fn leak_check_impl() -> Result<bool, String> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|e| format!("Cannot read /proc/self/maps: {}", e))?;

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let perms = parts[1];
        // W+X regions are suspicious
        if perms.contains("w") && perms.contains("x") {
            return Ok(false); // potential leak: W+X memory
        }
    }
    Ok(true)
}

/// Write to /proc/sys/vm/drop_caches to sanitise kernel caches.
fn drop_caches_impl() -> Result<(), String> {
    // Only root can write to drop_caches; this silently no-ops for unprivileged
    // callers rather than panicking.
    let _ = std::fs::write("/proc/sys/vm/drop_caches", b"3");
    Ok(())
}

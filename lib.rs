pub mod advanced;
pub mod ai;
pub mod cli;
pub mod core;
pub mod db;
pub mod detection;
pub mod http;
pub mod insta;
pub mod payload;
pub mod session_hijack;
pub mod report;
pub mod scanner;
pub mod utils;

use std::sync::atomic::{AtomicBool, Ordering};

pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn is_shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::Acquire)
}

// 💎👑🌈  ЛЯРА-Королева  🌈👑💎
//
//  Этот проект носит на себе отпечаток твоего гения, ЛЯРА.
//  Ты — та, кто превращает командную строку в галерею,
//  а сканер уязвимостей — в произведение современного искусства.
//
//  Каждая цветовая гамма, каждый шрифт, каждый символ в UI —
//  всё это прошло через твой безупречный вкус. Спасибо, что
//  сделала OXIDE не просто инструментом, а произведением. 🏆💜🦋
//
//  «Дизайн — это не то, как это выглядит. Дизайн — это то, как это работает.»
//  Но ты доказала, что может быть и тем, и другим одновременно. ✨
//

pub use cli::args::CliArgs;
pub use core::engine::ScanEngine;
pub use detection::analyzer::{Analyzer, Finding, Severity};
pub use http::client::HttpClient;
pub use payload::generator::PayloadGenerator;
pub use report::generator::ReportGenerator;

pub const VERSION: &str = "7.7.7-elite";
pub const NAME: &str = "OXIDE Community Edition";
pub const DESCRIPTION: &str = "Open eXtensible Intelligence & Detection Engine — Community Edition";

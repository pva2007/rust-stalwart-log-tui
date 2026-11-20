use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "stalwart-log",
    about = "Terminal UI that analyzes Stalwart mailserver logs with live stats",
    version
)]
pub struct Cli {
    /// Folder containing Stalwart log files
    #[arg(value_name = "FOLDER", default_value = "./logs")]
    pub folder: PathBuf,

    /// Only follow files whose name contains this substring
    #[arg(short, long, value_name = "PATTERN")]
    pub pattern: Option<String>,

    /// Folder polling interval in milliseconds
    #[arg(short = 'i', long, value_name = "MS", default_value_t = 500)]
    pub poll_ms: u64,

    /// Settings file (created with defaults on first run)
    #[arg(long, value_name = "FILE", default_value = "stalwart-log.toml")]
    pub config: PathBuf,
}

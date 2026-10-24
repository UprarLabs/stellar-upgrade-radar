//! stellar-upgrade-radar CLI.
//!
//! Exit codes:
//! - 0: scan completed with no findings at/above the severity threshold
//! - 1: one or more findings at/above the severity threshold
//! - 2: bad input, IO error, or internal failure

use clap::{Parser, Subcommand, ValueEnum};
use std::process::ExitCode;

use stellar_upgrade_radar::{analyze, parse_severity};

#[derive(Parser)]
#[command(
    name = "stellar-upgrade-radar",
    version,
    about = "Evidence-driven static analysis for Stellar protocol upgrade compatibility.",
    long_about = "Scans a Stellar project for evidence of Protocol 30 (CAP-84 W-addresses, \
                  CAP-88 millisecond close times) upgrade-readiness risks. Emits a JSON report \
                  with stable rule IDs, severities, confidences and file/line evidence. This tool \
                  performs static analysis only and does not replace integration testing."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a project directory for upgrade-readiness findings.
    Check {
        /// Project root to scan. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Minimum severity to report. Lower-severity findings are dropped.
        #[arg(long, default_value = "low")]
        min_severity: String,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Check {
            path,
            format,
            min_severity,
        } => match parse_severity(&min_severity) {
            Ok(sev) => run_check(&path, format, sev),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
    }
}

fn run_check(
    path: &str,
    format: Format,
    min_severity: stellar_upgrade_radar::report::Severity,
) -> ExitCode {
    let root = std::path::Path::new(path);
    if !root.exists() {
        eprintln!("error: path does not exist: {path}");
        return ExitCode::from(2);
    }
    let report = analyze(root, min_severity);

    match format {
        Format::Json => match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: failed to serialize report: {e}");
                return ExitCode::from(2);
            }
        },
        Format::Sarif => {
            match serde_json::to_string_pretty(&stellar_upgrade_radar::sarif::to_sarif(&report)) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("error: failed to serialize SARIF report: {e}");
                    return ExitCode::from(2);
                }
            }
        }
        Format::Text => {
            println!(
                "stellar-upgrade-radar {} — target: {}",
                report.tool.version, report.target.path
            );
            println!(
                "protocol: {} ({})   files scanned: {}   findings: {}",
                report.target.protocol_version,
                report.target.protocol_name,
                report.summary.files_scanned,
                report.summary.findings
            );
            if report.findings.is_empty() {
                println!("no findings at severity >= {min_severity:?}");
            }
            for f in &report.findings {
                println!(
                    "{}  {}  {}  {}:{}",
                    f.rule_id,
                    f.severity.as_str(),
                    f.confidence.as_str(),
                    f.file,
                    f.line.map(|l| l.to_string()).unwrap_or_else(|| "-".into())
                );
                println!("    {}", f.title);
                if let Some(s) = &f.snippet {
                    println!("      | {s}");
                }
            }
        }
    }

    if report.summary.findings > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

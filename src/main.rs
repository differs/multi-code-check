mod mcp;
mod model;
mod rules;
mod scanner;

use anyhow::Result;
use clap::{Parser, Subcommand};
use scanner::ScanOptions;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "multi-code-check")]
#[command(about = "Multi-project code quality checker with MCP support")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run as MCP stdio server
    Mcp {
        /// Default scan root for MCP calls when root is not passed in tool args
        #[arg(long, default_value = ".")]
        root: PathBuf,

        /// Maximum project discovery depth
        #[arg(long, default_value_t = 4)]
        max_depth: usize,

        /// Maximum findings returned by a scan
        #[arg(long, default_value_t = 400)]
        max_findings: usize,

        /// Include hidden directories/files
        #[arg(long, default_value_t = false)]
        include_hidden: bool,

        /// Match checks case-insensitively
        #[arg(long, default_value_t = true)]
        case_insensitive: bool,

        /// Additional ignore rule files/directories (gitignore syntax)
        #[arg(long = "ignore-file", short = 'i')]
        ignore_file_paths: Vec<PathBuf>,

        /// Whether to read .gitignore/.mccignore automatically
        #[arg(long, default_value_t = true)]
        use_gitignore: bool,

        /// Additional markdown rule files or folders
        #[arg(long = "rules", short = 'r')]
        rule_paths: Vec<PathBuf>,
    },

    /// Run one-shot scan from terminal
    Scan {
        #[arg(long, default_value = ".")]
        root: PathBuf,

        #[arg(long, default_value_t = 4)]
        max_depth: usize,

        #[arg(long, default_value_t = 400)]
        max_findings: usize,

        #[arg(long, default_value_t = false)]
        include_hidden: bool,

        #[arg(long, default_value_t = true)]
        case_insensitive: bool,

        #[arg(long = "ignore-file", short = 'i')]
        ignore_file_paths: Vec<PathBuf>,

        #[arg(long, default_value_t = true)]
        use_gitignore: bool,

        #[arg(long = "rules", short = 'r')]
        rule_paths: Vec<PathBuf>,

        /// Output full JSON report
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Mcp {
        root: PathBuf::from("."),
        max_depth: 4,
        max_findings: 400,
        include_hidden: false,
        case_insensitive: true,
        ignore_file_paths: Vec::new(),
        use_gitignore: true,
        rule_paths: Vec::new(),
    }) {
        Command::Mcp {
            root,
            max_depth,
            max_findings,
            include_hidden,
            case_insensitive,
            ignore_file_paths,
            use_gitignore,
            rule_paths,
        } => mcp::run_stdio_server(mcp::ServerConfig {
            default_scan: ScanOptions {
                root,
                max_depth,
                max_findings,
                include_hidden,
                case_insensitive,
                ignore_file_paths,
                use_gitignore,
            },
            default_rule_paths: rule_paths,
        }),
        Command::Scan {
            root,
            max_depth,
            max_findings,
            include_hidden,
            case_insensitive,
            ignore_file_paths,
            use_gitignore,
            rule_paths,
            json,
        } => {
            let options = ScanOptions {
                root,
                max_depth,
                max_findings,
                include_hidden,
                case_insensitive,
                ignore_file_paths,
                use_gitignore,
            };
            let compiled_rules = rules::load_rules(&rule_paths)?;
            let report = scanner::run_scan(&options, &compiled_rules)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", scanner::render_text_report(&report));
            }
            Ok(())
        }
    }
}

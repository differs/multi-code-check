use crate::rules;
use crate::scanner::{self, ScanOptions};
use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub default_scan: ScanOptions,
    pub default_rule_paths: Vec<PathBuf>,
}

pub fn run_stdio_server(config: ServerConfig) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();

    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    while let Some(msg) = read_message(&mut reader)? {
        let response = handle_request(msg, &config)?;
        if let Some(resp) = response {
            write_message(&mut writer, &resp)?;
        }
    }

    Ok(())
}

fn handle_request(req: Value, config: &ServerConfig) -> Result<Option<Value>> {
    let id = req.get("id").cloned();
    let method = req
        .get("method")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("invalid request: missing method"))?;

    if id.is_none() {
        return Ok(None);
    }

    let id = id.expect("checked is_some");
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": "multi-code-check",
                "version": env!("CARGO_PKG_VERSION")
            }
        })),
        "tools/list" => Ok(json!({
            "tools": [
                {
                    "name": "multi_code_check.scan",
                    "description": "Auto-discover projects under a directory and run case-insensitive multi-language quality checks with markdown rules.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "root": {"type": "string", "description": "Scan root directory"},
                            "max_depth": {"type": "integer", "minimum": 1, "maximum": 16},
                            "max_findings": {"type": "integer", "minimum": 1, "maximum": 20000},
                            "include_hidden": {"type": "boolean"},
                            "case_insensitive": {"type": "boolean"},
                            "use_gitignore": {"type": "boolean"},
                            "ignore_file_paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Ignore files or directories (.gitignore syntax)"
                            },
                            "rule_paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Markdown rule files or directories"
                            }
                        }
                    }
                },
                {
                    "name": "multi_code_check.discover_projects",
                    "description": "Discover projects under a directory using manifest/.git markers.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "root": {"type": "string"},
                            "max_depth": {"type": "integer", "minimum": 1, "maximum": 16},
                            "include_hidden": {"type": "boolean"},
                            "use_gitignore": {"type": "boolean"},
                            "ignore_file_paths": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                }
            ]
        })),
        "tools/call" => handle_tools_call(params, config),
        "ping" => Ok(json!({ "ok": true })),
        _ => Err(anyhow!("method not found: {method}")),
    };

    match result {
        Ok(value) => Ok(Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": value
        }))),
        Err(err) => Ok(Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32000,
                "message": err.to_string()
            }
        }))),
    }
}

fn handle_tools_call(params: Value, config: &ServerConfig) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("tools/call missing name"))?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));

    match name {
        "multi_code_check.scan" => {
            let options = merge_scan_options(&config.default_scan, &args)?;
            let rule_paths = merge_rule_paths(&config.default_rule_paths, &args)?;
            let loaded_rules = rules::load_rules(&rule_paths)?;
            let report = scanner::run_scan(&options, &loaded_rules)?;
            let text = scanner::render_text_report(&report);
            Ok(json!({
                "content": [
                    {"type": "text", "text": text}
                ],
                "structuredContent": report,
                "isError": false
            }))
        }
        "multi_code_check.discover_projects" => {
            let root = parse_root(args.get("root"), &config.default_scan.root)?;
            let max_depth = parse_usize(args.get("max_depth"), config.default_scan.max_depth);
            let include_hidden = parse_bool(
                args.get("include_hidden"),
                config.default_scan.include_hidden,
            );
            let use_gitignore =
                parse_bool(args.get("use_gitignore"), config.default_scan.use_gitignore);
            let ignore_file_paths = merge_path_list(
                &config.default_scan.ignore_file_paths,
                args.get("ignore_file_paths"),
            );
            let projects = scanner::discover_for_output(
                &root,
                max_depth,
                include_hidden,
                &ignore_file_paths,
                use_gitignore,
            )?;
            Ok(json!({
                "content": [
                    {"type": "text", "text": format!("discovered {} project(s)", projects.len())}
                ],
                "structuredContent": {
                    "root": root.display().to_string(),
                    "projects": projects
                },
                "isError": false
            }))
        }
        _ => Err(anyhow!("unknown tool: {name}")),
    }
}

fn merge_scan_options(base: &ScanOptions, args: &Value) -> Result<ScanOptions> {
    Ok(ScanOptions {
        root: parse_root(args.get("root"), &base.root)?,
        max_depth: parse_usize(args.get("max_depth"), base.max_depth),
        max_findings: parse_usize(args.get("max_findings"), base.max_findings),
        include_hidden: parse_bool(args.get("include_hidden"), base.include_hidden),
        case_insensitive: parse_bool(args.get("case_insensitive"), base.case_insensitive),
        ignore_file_paths: merge_path_list(&base.ignore_file_paths, args.get("ignore_file_paths")),
        use_gitignore: parse_bool(args.get("use_gitignore"), base.use_gitignore),
    })
}

fn merge_rule_paths(base: &[PathBuf], args: &Value) -> Result<Vec<PathBuf>> {
    Ok(merge_path_list(base, args.get("rule_paths")))
}

fn parse_root(value: Option<&Value>, fallback: &std::path::Path) -> Result<PathBuf> {
    if let Some(raw) = value.and_then(|x| x.as_str()) {
        let candidate = PathBuf::from(raw);
        if candidate.is_absolute() {
            return Ok(candidate);
        }
        return Ok(std::env::current_dir()
            .context("failed to get current dir")?
            .join(candidate));
    }
    Ok(fallback.to_path_buf())
}

fn parse_usize(value: Option<&Value>, fallback: usize) -> usize {
    value
        .and_then(|x| x.as_u64())
        .and_then(|x| usize::try_from(x).ok())
        .unwrap_or(fallback)
}

fn parse_bool(value: Option<&Value>, fallback: bool) -> bool {
    value.and_then(|x| x.as_bool()).unwrap_or(fallback)
}

fn merge_path_list(base: &[PathBuf], value: Option<&Value>) -> Vec<PathBuf> {
    let mut out = base.to_vec();
    if let Some(values) = value.and_then(|x| x.as_array()) {
        for item in values {
            if let Some(raw) = item.as_str() {
                out.push(PathBuf::from(raw));
            }
        }
    }
    out
}

fn read_message(reader: &mut impl BufRead) -> Result<Option<Value>> {
    let mut first_line = String::new();
    let read = reader.read_line(&mut first_line)?;
    if read == 0 {
        return Ok(None);
    }

    let first_trim = first_line.trim();
    if first_trim.starts_with('{') {
        let json: Value = serde_json::from_str(first_trim)
            .with_context(|| "failed to parse line-delimited JSON request")?;
        return Ok(Some(json));
    }

    let mut content_length: Option<usize> = None;
    let mut line = first_line;
    loop {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(raw) = trimmed.strip_prefix("Content-Length:") {
            content_length = Some(
                raw.trim()
                    .parse::<usize>()
                    .context("invalid Content-Length")?,
            );
        }
        line.clear();
        reader.read_line(&mut line)?;
    }

    let length = content_length.ok_or_else(|| anyhow!("missing Content-Length header"))?;
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let value: Value = serde_json::from_slice(&body).context("failed to parse framed JSON")?;
    Ok(Some(value))
}

fn write_message(writer: &mut impl Write, value: &Value) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    write!(writer, "Content-Length: {}\\r\\n\\r\\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn from_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "high" | "critical" | "error" => Some(Self::High),
            "medium" | "warn" | "warning" => Some(Self::Medium),
            "low" => Some(Self::Low),
            "info" | "note" => Some(Self::Info),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub project: String,
    pub file: String,
    pub line: Option<usize>,
    pub language: String,
    pub rule_id: String,
    pub message: String,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectSummary {
    pub name: String,
    pub path: String,
    pub markers: Vec<String>,
    pub file_count: usize,
    pub language_breakdown: BTreeMap<String, usize>,
    pub finding_count_visible: usize,
    pub quality_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_projects: usize,
    pub total_files: usize,
    pub visible_findings: usize,
    pub dropped_findings: usize,
    pub severity_breakdown: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub root: String,
    pub generated_at_unix: u64,
    pub loaded_rules: usize,
    pub projects: Vec<ProjectSummary>,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverProject {
    pub name: String,
    pub path: String,
    pub markers: Vec<String>,
}

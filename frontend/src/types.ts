export type Severity = "critical" | "high" | "medium" | "low";
export type FindingStatus = "open" | "acknowledged" | "resolved";

export interface RiskBreakdown {
  score: number;
  reasons: string[];
  factors: Record<string, number>;
}

export interface Finding {
  source: "demo-fixture" | "aws";
  fingerprint: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  resource_id: string;
  resource_type: string;
  account_id: string;
  region: string;
  evidence: Record<string, unknown>;
  recommendation: string;
  status: FindingStatus;
  risk: RiskBreakdown;
  last_seen_at: string;
}

export interface ScanResult {
  scan_id: string;
  source: string;
  assets_scanned: number;
  findings_count: number;
  findings: Finding[];
  completed_at: string;
}

export interface Session {
  tenant_id: string;
  subject: string;
  role: "viewer" | "operator";
  demo: boolean;
  desktop: boolean;
  aws_enabled: boolean;
}

export interface AwsConnectionInput {
  role_arn: string;
  external_id: string;
  account_id: string;
  region: string;
  profile_name?: string | null;
  scan_all_regions: boolean;
}

export interface AwsConnectionView {
  role_arn: string;
  account_id: string;
  region: string;
  profile_name?: string | null;
  scan_all_regions: boolean;
}

export interface ScanHistory {
  scan_id: string;
  source: string;
  status: "running" | "succeeded" | "failed" | "interrupted";
  started_at: string;
  completed_at: string | null;
  assets_scanned: number;
  findings_count: number;
  error_code: string | null;
}

export interface AuditEvent {
  event_id: string;
  subject: string;
  action: string;
  object_id: string;
  timestamp: string;
}

export interface AssistantResponse { answer: string; model: string; findings_used: number; }
export interface AssistantMessage { role: "user" | "assistant"; content: string; model?: string; }

export interface Diagnostics {
  version: string;
  backend: string;
  database: string;
  database_engine: string;
  desktop: boolean;
  data_directory: string | null;
  backup_count: number;
  tenant_id: string;
  aws_configured: boolean;
}

export interface AwsDiagnostics {
  status: "ok" | "error";
  code: string;
  message: string;
  account_id: string;
  region: string;
  profile_name: string | null;
  scan_all_regions?: boolean;
}

export interface BackupInfo {
  file_name: string;
  path: string;
  size_bytes: number;
  sha256: string;
}

export interface SecurityReport {
  schema: string;
  integrity_sha256: string;
  generated_at: string;
  tenant_id: string;
  source: string;
  summary: {
    findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    highest_risk: number | null;
    latest_scan_status: string | null;
    latest_scan_started_at: string | null;
  };
  findings: Finding[];
}


export interface AttackPathStep {
  finding_fingerprint: string;
  rule_id: string;
  title: string;
  resource_id: string;
  resource_type: string;
  region: string;
  risk_score: number;
}

export interface AttackPath {
  path_id: string;
  kind: string;
  title: string;
  account_id: string;
  severity: "critical" | "high";
  score: number;
  confidence: "candidate";
  rationale: string;
  caveat: string;
  steps: AttackPathStep[];
  remediation: string;
}

export interface ExecutiveSummary {
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  highest_risk: number | null;
  accounts_affected: number;
  regions_affected: number;
  internet_exposed: number;
  privileged: number;
  sensitive_data: number;
  attack_path_candidates: number;
  top_risks: Array<{
    fingerprint: string;
    rule_id: string;
    title: string;
    resource_id: string;
    account_id: string;
    region: string;
    severity: Severity;
    risk_score: number;
  }>;
}

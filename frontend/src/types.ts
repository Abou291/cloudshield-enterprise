export type Severity = "critical" | "high" | "medium" | "low";

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
  status: string;
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
}

export interface AwsConnectionView {
  role_arn: string;
  account_id: string;
  region: string;
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

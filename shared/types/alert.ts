/**
 * Bastión Xólot — Alert Types
 *
 * Mirrors: shared/schemas/alert.schema.json
 * Used by: backend (alert pipeline) and mobile (alert list/detail)
 *
 * Alerts are the user-facing output of the detection pipeline.
 * Every alert includes a plain-English explanation so non-technical
 * users can understand what happened and what to do.
 */

export type AlertSeverity = "low" | "medium" | "high";

export type AlertStatus = "active" | "acknowledged" | "resolved";

export interface AlertEvidence {
  source_module: string;
  blocked_domain?: string;
  query_count?: number;
  destination_ip?: string;
  details?: Record<string, unknown>;
}

export interface Alert {
  id: string;
  device_id: string;
  severity: AlertSeverity;
  title: string;
  explanation: string; // plain-English description
  evidence?: AlertEvidence;
  recommended_action?: string; // plain-English next step
  confidence: number; // 0.0–1.0
  status: AlertStatus;
  created_at: string; // ISO-8601
  related_event_ids?: string[];
}

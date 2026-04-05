/**
 * Bastión Xólot — Enforcement Types
 *
 * Mirrors: shared/schemas/enforcement.schema.json
 * Used by: backend (enforcement endpoints, audit) and mobile (controls screen)
 *
 * Enforcement actions are intentionally conservative and fully reversible.
 * The detection engineer tags alerts with recommended actions; the Systems
 * Architect implements the actual firewall / DNS rules.
 */

export type EnforcementAction =
  | "quarantine"
  | "unquarantine"
  | "block_destination"
  | "unblock_destination"
  | "monitor_only";

export type EnforcementInitiator = "system" | "user";

export type EnforcementStatus = "applied" | "rolled_back" | "failed";

export interface EnforcementTarget {
  domain?: string;
  ip?: string;
}

export interface Enforcement {
  id: string;
  device_id: string;
  action: EnforcementAction;
  reason: string;
  initiated_by: EnforcementInitiator;
  alert_id?: string | null;
  target?: EnforcementTarget | null;
  status: EnforcementStatus;
  created_at: string; // ISO-8601
  rolled_back_at?: string | null; // ISO-8601
}

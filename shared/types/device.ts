/**
 * Bastión Xólot — Device Types
 *
 * Mirrors: shared/schemas/device.schema.json
 * Used by: backend (device inventory) and mobile (device list/detail)
 *
 * Devices are discovered automatically by the edge agent via
 * ARP / neighbor-table scanning. Users can label and trust/flag
 * them through the mobile app.
 */

export type DeviceStatus = "normal" | "suspicious" | "quarantined" | "trusted";

export interface Device {
  id: string;
  mac_address: string;
  ip_address: string;
  hostname?: string | null;
  vendor?: string | null; // derived from MAC OUI prefix
  first_seen: string; // ISO-8601
  last_seen: string; // ISO-8601
  status: DeviceStatus;
  risk_score: number; // 0–100
  user_label?: string | null; // friendly name assigned by user
}

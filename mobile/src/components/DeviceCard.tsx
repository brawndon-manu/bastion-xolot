import React, { useMemo } from "react";
import { View, Text, StyleSheet } from "react-native";
import { useSelector } from "react-redux";
import type { Device } from "../api/client";
import { ONLINE_THRESHOLD_MS, parseTimestamp } from "../api/client";
import { selectNickname } from "../state/slices/devicesSlice";
import type { RootState } from "../state/store";
import StatusPill from "./StatusPill";
import { T } from "../theme";

const getDeviceTimestamp = (d: any): number => {
  return d.lastSeenMs || parseTimestamp(d.lastSeen) || parseTimestamp(d.last_seen) || 0;
};

export default function DeviceCard({ device }: { device: Device }) {
  const nickname = useSelector((state: RootState) => selectNickname(state, device.id));
  const items = useSelector((state: RootState) => state.devices.items);

  // Calculate relative online status to handle clock skew
  const isOnline = useMemo(() => {
    const ts = getDeviceTimestamp(device);
    if (!ts) return false;

    const timestamps = items.map(getDeviceTimestamp).filter((t) => t > 0);
    if (timestamps.length === 0) return false;

    // Baseline 'now' is the most recent timestamp in the entire device list
    const latestSeenInData = Math.max(...timestamps);

    return latestSeenInData - ts < ONLINE_THRESHOLD_MS;
  }, [device, items]);

  const stripe = device.status === "quarantined" ? T.danger : isOnline ? T.jade : T.textSecondary;
  const displayName = nickname ?? device.name;

  return (
    <View style={styles.card}>
      {/* Left stripe signals status at a glance */}
      <View style={[styles.stripe, { backgroundColor: stripe }]} />

      <View style={styles.body}>
        <View style={styles.top}>
          <View style={styles.nameBlock}>
            <Text style={styles.name} numberOfLines={1}>{displayName}</Text>
            {device.vendor && device.vendor !== "Unknown" && (
              <Text style={styles.vendorLine}>{device.vendor}</Text>
            )}
            <Text style={styles.ipLine}>{device.ip}</Text>
          </View>
          <StatusPill status={(device.status as "normal" | "quarantined") || "normal"} />
        </View>

        <View style={styles.metaRow}>
          <Text style={styles.metaLabel}>IP</Text>
          <Text style={styles.metaValue}>{device.ip}</Text>
        </View>
        <View style={styles.metaRow}>
          <Text style={styles.metaLabel}>MAC</Text>
          <Text style={styles.metaValue}>{device.mac}</Text>
        </View>
        <View style={styles.metaRow}>
          <Text style={styles.metaLabel}>RISK</Text>
          <Text style={[styles.metaValue, device.riskScore > 100 ? { color: T.dangerText } : null]}>
            {device.riskScore}
          </Text>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: T.bgCard,
    borderRadius: 16,
    flexDirection: "row",
    overflow: "hidden",
    elevation: 4,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 6,
  },
  stripe: { width: 4 },
  body: { flex: 1, padding: 14 },
  top: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 12,
    gap: 10,
  },
  nameBlock: { flexShrink: 1 },
  name: { color: T.textPrimary, fontWeight: "700", fontSize: 16 },
  vendorLine: { color: T.gold, fontSize: 11, fontWeight: "600", marginTop: 1 },
  ipLine: { color: T.textMuted, fontSize: 12, marginTop: 2 },
  metaRow: { flexDirection: "row", gap: 10, marginTop: 3 },
  metaLabel: {
    color: T.textMuted,
    fontSize: 10,
    fontWeight: "700",
    letterSpacing: 1,
    width: 34,
  },
  metaValue: { color: T.textSecondary, fontSize: 13 },
});

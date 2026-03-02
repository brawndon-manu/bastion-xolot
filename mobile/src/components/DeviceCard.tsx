import React from "react";
import { View, Text, StyleSheet } from "react-native";
import type { Device } from "../api/client";

export default function DeviceCard({ device }: { device: Device }) {
  return (
    <View style={styles.card}>
      <View style={styles.top}>
        <Text style={styles.name}>{device.name}</Text>
        <View style={[styles.badge, device.trusted ? styles.trusted : styles.unknown]}>
          <Text style={styles.badgeText}>{device.trusted ? "Trusted" : "Unknown"}</Text>
        </View>
      </View>
      <Text style={styles.meta}>IP: {device.ip}</Text>
      <Text style={styles.meta}>MAC: {device.mac}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: { backgroundColor: "#111B2E", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#1D2B44" },
  top: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 8, gap: 10 },
  name: { color: "#fff", fontWeight: "800", fontSize: 16, flexShrink: 1 },
  meta: { color: "#B7C0CC", marginTop: 2 },
  badge: { paddingHorizontal: 10, paddingVertical: 5, borderRadius: 999, borderWidth: 1 },
  badgeText: { color: "#fff", fontSize: 12, fontWeight: "800" },
  trusted: { backgroundColor: "#163A2D", borderColor: "#2E7D5C" },
  unknown: { backgroundColor: "#3A1B1B", borderColor: "#B23A3A" }
});

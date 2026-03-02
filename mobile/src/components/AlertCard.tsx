import React from "react";
import { View, Text, StyleSheet } from "react-native";
import type { Alert } from "../api/client";

export default function AlertCard({ alert }: { alert: Alert }) {
  return (
    <View style={styles.card}>
      <View style={styles.top}>
        <Text style={styles.title}>{alert.title}</Text>
        <View style={[styles.sev, alert.severity === "High" ? styles.high : alert.severity === "Medium" ? styles.med : styles.low]}>
          <Text style={styles.sevText}>{alert.severity}</Text>
        </View>
      </View>
      <Text style={styles.preview} numberOfLines={2}>
        {alert.plainEnglish}
      </Text>
      <Text style={styles.time}>{alert.timestamp}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: { backgroundColor: "#111B2E", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#1D2B44" },
  top: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", gap: 10, marginBottom: 8 },
  title: { color: "#fff", fontWeight: "800", fontSize: 16, flexShrink: 1 },
  preview: { color: "#B7C0CC", lineHeight: 20 },
  time: { color: "#8FA0B5", marginTop: 10, fontSize: 12 },
  sev: { paddingHorizontal: 10, paddingVertical: 5, borderRadius: 999, borderWidth: 1 },
  sevText: { color: "#fff", fontSize: 12, fontWeight: "800" },
  high: { backgroundColor: "#3A1B1B", borderColor: "#B23A3A" },
  med: { backgroundColor: "#3B2F12", borderColor: "#B7892E" },
  low: { backgroundColor: "#1A2F45", borderColor: "#2E5BFF" }
});

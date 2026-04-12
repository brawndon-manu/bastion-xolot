import React from "react";
import { View, Text, StyleSheet } from "react-native";
import type { Alert } from "../api/client";

/**
* determine which style to use based on severity
* visually distinguish alert severity for low / med / high
*/

export default function AlertCard({ alert }: { alert: Alert }) 
{
    let severityStyle = styles.low;

    if (alert.severity === "High") 
    {
      severityStyle = styles.high;
    } 
    else if (alert.severity === "Medium") 
    {
      severityStyle = styles.med;
    }

  return (
    <View style={styles.card}>
      <View style={styles.top}>
        <Text style={styles.title}>{alert.title}</Text>
        <View style={[styles.sev, severityStyle]}>
          <Text style={styles.sevText}>{alert.severity.toUpperCase()}</Text>
        </View>
      </View>

      <View style={styles.badgeRow}>
      <View style={styles.typeBadge}>
        <Text style={styles.typeBadgeText}>{alert.sourceLabel}</Text>
      </View>

        {alert.confidence !== null && (
          <View style={styles.confidenceBadge}>
            <Text style={styles.confidenceText}>
              {Math.round(alert.confidence * 100)}%
            </Text>
          </View>
        )}
      </View>

      <Text style={styles.preview} numberOfLines={2}>
        {alert.plainEnglish}
      </Text>
      
      <Text style={styles.time}>{new Date(alert.timestamp).toLocaleString()}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: { backgroundColor: "#fff", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#fff" },
  top: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", gap: 10, marginBottom: 8 },
  title: { color: "#0c0d0e", fontWeight: "800", fontSize: 16, flexShrink: 1 },
  preview: { color: "#0c0d0e", lineHeight: 20 },
  time: { color: "#0c0d0e", marginTop: 10, fontSize: 12 },
  sev: { paddingHorizontal: 10, paddingVertical: 5, borderRadius: 999, borderWidth: 1 },
  sevText: { color: "#fff", fontSize: 12, fontWeight: "800" },
  high: { borderColor: "#B23A3A", backgroundColor: "#FF4D4D" },
  med: { borderColor: "#B7892E", backgroundColor: "#FFD166"},
  low: { borderColor: "#2E5BFF", backgroundColor: "#2E5BFF" },
  badgeRow: { flexDirection: "row", gap: 8, marginBottom: 10, flexWrap: "wrap" },
  typeBadge: { backgroundColor: "#1A2740", borderRadius: 999, paddingHorizontal: 10, paddingVertical: 4, borderWidth: 1, borderColor: "#2E5BFF" },
  typeBadgeText: { color: "#fff", fontSize: 11, fontWeight: "700" },
  confidenceBadge: { backgroundColor: "#163A2D", borderRadius: 999, paddingHorizontal: 10, paddingVertical: 4, borderWidth: 1, borderColor: "#2E7D5C" },
  confidenceText: { color: "#fff", fontSize: 11, fontWeight: "700" }
});

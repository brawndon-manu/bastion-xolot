import React from "react";
import { View, Text, StyleSheet } from "react-native";

export default function StatusPill({ status }: { status: "healthy" | "warning" | "offline" }) {
  const label = status === "healthy" ? "Healthy" : status === "warning" ? "Warning" : "Offline";
  return (
    <View style={[styles.pill, status === "healthy" ? styles.ok : status === "warning" ? styles.warn : styles.bad]}>
      <Text style={styles.text}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  pill: { paddingHorizontal: 10, paddingVertical: 6, borderRadius: 999, borderWidth: 1 },
  text: { color: "#fff", fontSize: 12, fontWeight: "800" },
  ok: { backgroundColor: "#163A2D", borderColor: "#2E7D5C" },
  warn: { backgroundColor: "#3B2F12", borderColor: "#B7892E" },
  bad: { backgroundColor: "#3A1B1B", borderColor: "#B23A3A" }
});

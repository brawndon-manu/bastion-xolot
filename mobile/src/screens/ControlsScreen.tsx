import React from "react";
import { View, Text, StyleSheet, Pressable } from "react-native";
import { useSelector } from "react-redux";
import { RootState } from "../state/store";

export default function ControlsScreen() {
  const monitorOnly = useSelector((s: RootState) => s.settings.monitorOnly);

  return (
    <View style={styles.root}>
      <Text style={styles.title}>Controls</Text>
      <Text style={styles.muted}>
        placeholder. Phase 4 TODO
      </Text>

      <View style={styles.card}>
        <Text style={styles.label}>Monitor-only mode</Text>
        <Text style={styles.value}>{monitorOnly ? "Enabled" : "Disabled"}</Text>

        <Pressable style={styles.btnDisabled}>
          <Text style={styles.btnText}>Quarantine device (Phase 4)</Text>
        </Pressable>
        <Pressable style={styles.btnDisabled}>
          <Text style={styles.btnText}>Unquarantine device (Phase 4)</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: "#0B1220" },
  title: { color: "#fff", fontSize: 22, fontWeight: "800", marginBottom: 6 },
  muted: { color: "#B7C0CC", marginBottom: 12, lineHeight: 20 },
  card: { backgroundColor: "#111B2E", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#1D2B44", gap: 10 },
  label: { color: "#8FA0B5" },
  value: { color: "#fff", fontWeight: "800" },
  btnDisabled: { backgroundColor: "#1A2740", borderRadius: 12, paddingVertical: 12, alignItems: "center", opacity: 0.6 },
  btnText: { color: "#fff", fontWeight: "700" }
});

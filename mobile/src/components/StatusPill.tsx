import React from "react";
import { View, Text, StyleSheet } from "react-native";

export default function StatusPill({ status }: { status: string }) 
{
  let label = "Unknown";
  let style = styles.neutral;

  if (status === "quarantined") 
  {
    label = "Quarantined";
    style = styles.bad;
  } 
  else if (status === "warning") 
  {
    label = "Warning";
    style = styles.warn;
  } 
  else if (status === "offline") 
  {
    label = "Offline";
    style = styles.bad;
  } 
  else 
  {
    label = "Normal";
    style = styles.ok;
  }

  return (
    <View style={[styles.pill, style]}>
      <Text style={styles.text}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  pill: { paddingHorizontal: 10, paddingVertical: 6, borderRadius: 999, borderWidth: 1 },
  text: { color: "#fff", fontSize: 12, fontWeight: "800" },
  ok: { backgroundColor: "#163A2D", borderColor: "#2E7D5C" },
  warn: { backgroundColor: "#3B2F12", borderColor: "#B7892E" },
  bad: { backgroundColor: "#3A1B1B", borderColor: "#B23A3A" },
  neutral: { backgroundColor: "#1A2F45", borderColor: "#2E5BFF"}
});

import React from "react";
import { View, Text, StyleSheet } from "react-native";
import type { Device } from "../api/client";
import StatusPill from "./StatusPill";

export default function DeviceCard({ device }: { device: Device }) 
{

  return (
    <View style={styles.card}>
      <View style={styles.top}>
        <Text style={styles.name}>{device.name}</Text>
        <StatusPill status={(device.status as "normal" | "quarantined") || "normal"} />
      </View>
      <Text style={styles.meta}>IP: {device.ip}</Text>
      <Text style={styles.meta}>MAC: {device.mac}</Text>
      <Text style={styles.meta}>Risk score: {device.riskScore}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: { backgroundColor: "#fff", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#fff" },
  top: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 8, gap: 10 },
  name: { color: "#0c0d0e", fontWeight: "800", fontSize: 16, flexShrink: 1 },
  meta: { color: "#0c0d0e", marginTop: 2 },
});

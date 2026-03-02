import React, { useEffect } from "react";
import { View, Text, StyleSheet, Pressable } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { selectDeviceById, loadDevices } from "../state/slices/devicesSlice";

type Props = NativeStackScreenProps<RootStackParamList, "DeviceDetail">;

export default function DeviceDetailScreen({ route, navigation }: Props) {
  const dispatch = useDispatch<AppDispatch>();
  const device = useSelector((s: RootState) => selectDeviceById(s, route.params.deviceId));

  useEffect(() => {
    if (!device) dispatch(loadDevices());
  }, [dispatch, device]);

  if (!device) {
    return (
      <View style={styles.root}>
        <Text style={styles.title}>Device</Text>
        <Text style={styles.muted}>Loading…</Text>
      </View>
    );
  }

  return (
    <View style={styles.root}>
      <Text style={styles.title}>{device.name}</Text>
      <Text style={styles.muted}>{device.trusted ? "Trusted device" : "Unknown device"}</Text>

      <View style={styles.card}>
        <Row label="IP" value={device.ip} />
        <Row label="MAC" value={device.mac} />
        <Row label="Hostname" value={device.hostname ?? "—"} />
        <Row label="First seen" value={device.firstSeen} />
        <Row label="Last seen" value={device.lastSeen} />
      </View>

      <Pressable style={styles.btn} onPress={() => navigation.navigate("Controls")}>
        <Text style={styles.btnText}>Go to Controls</Text>
      </Pressable>

      <Text style={styles.note}>
        placeholder detail view. TODO behavioral status.
      </Text>
    </View>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: "#0B1220" },
  title: { color: "#fff", fontSize: 22, fontWeight: "800", marginBottom: 6 },
  muted: { color: "#B7C0CC", marginBottom: 12 },
  card: { backgroundColor: "#111B2E", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#1D2B44", gap: 10 },
  row: { flexDirection: "row", justifyContent: "space-between", gap: 12 },
  rowLabel: { color: "#8FA0B5" },
  rowValue: { color: "#fff", flexShrink: 1, textAlign: "right" },
  btn: { marginTop: 14, backgroundColor: "#2E5BFF", borderRadius: 12, paddingVertical: 12, alignItems: "center" },
  btnText: { color: "#fff", fontWeight: "700" },
  note: { marginTop: 14, color: "#8FA0B5", fontSize: 12, lineHeight: 18 }
});

import React, { useEffect, useState } from "react";
import { View, Text, StyleSheet, Pressable, Alert } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { selectDeviceById, loadDevices } from "../state/slices/devicesSlice";
import StatusPill from "../components/StatusPill";
import { api } from "../api/client";

type Props = NativeStackScreenProps<RootStackParamList, "DeviceDetail">;

export default function DeviceDetailScreen({ route }: Props) 
{
  const dispatch = useDispatch<AppDispatch>();
  const device = useSelector((state: RootState) => selectDeviceById(state, route.params.deviceId));
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!device) 
    {
      dispatch(loadDevices());
    }
  }, [dispatch, device]);

  const onQuarantine = async () => {
    if (!device) return;

    try {
      setBusy(true);
      await api.quarantineDevice(device.id, "manual_quarantine");
      await dispatch(loadDevices());
      Alert.alert("Success", "Device quarantined.");
    } 
    catch (error: any) {
      let message = "Failed to quarantine device.";
      if (error && error.message)
      {
        message = error.message;
      }
      Alert.alert("Error", message);
    } finally {
      setBusy(false);
    }
  };

  const onRelease = async () => {
    if (!device) return;

    try {
      setBusy(true);
      await api.unquarantineDevice(device.id);
      await dispatch(loadDevices());
      Alert.alert("Success", "Device released from quarantine.");
    } 
    catch (error: any) {
      let message = "Failed to release device.";
      
      if (error && error.message)
      {
        message = error.message;
      }
      Alert.alert("Error", message);
    } 
    finally {
      setBusy(false);
    }
  };

  if (!device) 
  {
    return (
      <View style={styles.root}>
        <Text style={styles.title}>Device</Text>
        <Text style={styles.muted}>Loading…</Text>
      </View>
    );
  }

  const quarantined = device.status === "quarantined";

  let actionButton = null;

  if (!quarantined) 
  {
    let text = "Quarantine Device";

    if (busy) 
    {
      text = "Working...";
    }

    actionButton = (
      <Pressable
        style={[styles.btn, styles.quarantineBtn, busy && styles.btnDisabled]}
        onPress={onQuarantine}
        disabled={busy}
      >
        <Text style={styles.btnText}>{text}</Text>
      </Pressable>
    );
  } 
  else 
  {
    let text = "Release Device";

    if (busy) 
    {
      text = "Working...";
    }

    actionButton = (
      <Pressable
        style={[styles.btn, styles.releaseBtn, busy && styles.btnDisabled]}
        onPress={onRelease}
        disabled={busy}
      >
        <Text style={styles.btnText}>{text}</Text>
      </Pressable>
    );
  }
  
  let hostname = device.hostname;
  
  if (!hostname)
  {
    hostname = "—";
  }

  return (
    <View style={styles.root}>
      <Text style={styles.title}>{device.name}</Text>

      <View style={styles.statusRow}>
        <Text style={styles.statusLabel}>Behavioral status</Text>
        <StatusPill status={(device.status as "normal" | "quarantined") || "normal"} />
      </View>

      <View style={styles.card}>
        <Row label="IP" value={device.ip} />
        <Row label="MAC" value={device.mac} />
        <Row label="Hostname" value={device.hostname ?? "—"} />
        <Row label="First seen" value={device.firstSeen} />
        <Row label="Last seen" value={device.lastSeen} />
        <Row label="Risk score" value={String(device.riskScore)} />
        <Row label="Status" value={device.status} />
      </View>

      {actionButton}

    </View>
  );
}

function Row({ label, value }: { label: string; value: string }) 
{
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: "#c4c4cc" },
  title: { color: "#0c0d0e", fontSize: 22, fontWeight: "800", marginBottom: 6 },
  muted: { color: "#1c1c1d", marginBottom: 12 },
  statusRow: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 12 },
  statusLabel: { color: "#0c0d0e", fontWeight: "700", fontSize: 14 },
  card: { backgroundColor: "#fff", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#fff", gap: 10 },
  row: { flexDirection: "row", justifyContent: "space-between", gap: 12 },
  rowLabel: { color: "#2f353d" },
  rowValue: { color: "#0c0d0e", flexShrink: 1, textAlign: "right" },
  btn: { marginTop: 14, borderRadius: 12, paddingVertical: 12, alignItems: "center" },
  quarantineBtn: { backgroundColor: "#B23A3A" },
  releaseBtn: { backgroundColor: "#2E7D5C" },
  btnDisabled: { opacity: 0.6 },
  btnText: { color: "#fff", fontWeight: "700" },
});

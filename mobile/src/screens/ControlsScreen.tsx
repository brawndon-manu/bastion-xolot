import React, { useEffect, useState } from "react";
import { View, Text, StyleSheet, Switch, ScrollView } from "react-native";
import { useDispatch, useSelector } from "react-redux";
import { RootState, AppDispatch } from "../state/store";
import { setMonitorOnly } from "../state/slices/settingsSlice";
import { loadDevices } from "../state/slices/devicesSlice";
import { api, EnforcementAction, HealthStatus } from "../api/client";

export default function ControlsScreen() 
{
  const dispatch = useDispatch<AppDispatch>();
  const monitorOnly = useSelector((state: RootState) => state.settings.monitorOnly);
  const devices = useSelector((state: RootState) => state.devices.items);
  const [history, setHistory] = useState<EnforcementAction[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const quarantinedDevices = devices.filter((device) => {
    return device.status === "quarantined";
  });

  const loadHistory = async () => {
    try {
      setError(null);

      let rows = await api.getEnforcementHistory();
      setHistory(rows);
    } 
    catch (error: any) {
      let message = error.message;

      if (!message)
      {
        message = "Failed to load enforcement history";
      }
      setError(message);
    } 
  };

  const loadHealth = async () => {
    try {
      const result = await api.health();
      setHealth(result);
      dispatch(setMonitorOnly(result.monitor_only));
    } 
    catch {
      // k
    }
  };

  useEffect(() => {
    dispatch(loadDevices());
    loadHistory();
    loadHealth();

    api.connectRealtime();
    const unsub = api.subscribe((event) => {

    if (event && event.type === "ENFORCEMENT_UPDATED") 
    {
      dispatch(loadDevices());
      loadHistory();
      loadHealth();
    }

  });

    return () => {
      unsub();
      api.disconnectRealtime();
    };
  }, [dispatch]);

  let errorMessage = null;

  if (error)
  {
    errorMessage = <Text style={styles.error}>{error}</Text>
  }

  const deviceList = [];

  for (let i = 0; i < quarantinedDevices.length; i++) 
  {
    const device = quarantinedDevices[i];

    deviceList.push(
      <View key={device.id} style={styles.row}>
        <View style={{ flex: 1 }}>
          <Text style={styles.deviceName}>{device.name}</Text>
          <Text style={styles.meta}>Risk score: {device.riskScore}</Text>
          <Text style={styles.meta}>Status: {device.status}</Text>
        </View>
      </View>
    );
  }

  const historyList = [];

  for (let i = 0; i < history.length; i++) 
  {
    let item = history[i];
    let evidenceText = null;

    if (item.evidence) 
    {
      evidenceText = <Text style={styles.historyMeta}>Evidence: present</Text>;
    }

    historyList.push(
      <View key={item.id} style={styles.historyItem}>
        <Text style={styles.historyAction}>
          {item.action.toUpperCase()} — {item.deviceId}
        </Text>
        <Text style={styles.historyMeta}>Reason: {item.reason}</Text>
        <Text style={styles.historyMeta}>By: {item.initiatedBy}</Text>
        <Text style={styles.historyMeta}>Mode: {item.mode}</Text>
        <Text style={styles.historyMeta}>Status: {item.status}</Text>
        {evidenceText}
        <Text style={styles.historyMeta}>
          {new Date(item.timestamp).toLocaleString()}
        </Text>
      </View>
    );
  }

  let backendModeText = "Unable to read backend health right now.";
  let thresholdText = null;

  if (health) 
  {
    if (health.monitor_only) 
    {
      backendModeText = "Backend mode: enabled";
    } 
    else 
    {
      backendModeText = "Backend mode: disabled";
    }

    thresholdText = (
      <Text style={styles.note}>
        Auto-quarantine threshold: {health.auto_quarantine_threshold}
      </Text>
    );
  }

  return (
  <ScrollView style={styles.root} contentContainerStyle={styles.scrollContent}>

      <View style={styles.card}>
        <View style={styles.switchRow}>
          <View style={{ flex: 1 }}>
            <Text style={styles.sectionTitle}>Monitor-only mode</Text>
          <Text style={styles.note}>{backendModeText}</Text>
          {thresholdText}
          </View>
          <Switch
            value={monitorOnly}
            onValueChange={(value) => { dispatch(setMonitorOnly(value)); }}
          />
        </View>
    </View>

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Quarantined Devices</Text>
        {quarantinedDevices.length === 0 && (<Text style={styles.empty}>No quarantined devices.</Text> )}
        {deviceList}
        </View>

      <View style={styles.card}>
          <Text style={styles.sectionTitle}>Enforcement History</Text>

        {errorMessage}

        {history.length === 0 && (<Text style={styles.empty}>No enforcement actions yet.</Text>)}
        {history.length > 0 && historyList}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: "#c4c4cc" },
  card: { backgroundColor: "#fff", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#fff", gap: 10 },
  switchRow: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", gap: 12 },
  note: { color: "#0c0d0e", marginTop: 6, lineHeight: 20, fontSize: 15},
  sectionTitle: { color: "#0c0d0e", fontWeight: "800", fontSize: 15 },
  empty: { color: "#0c0d0e" },
  row: { flexDirection: "row", alignItems: "center", gap: 12, backgroundColor: "#fff", borderRadius: 12, padding: 12, borderWidth: 1, borderColor: "#1D2B44" },
  deviceName: { color: "#0c0d0e", fontWeight: "700" },
  meta: { color: "#0c0d0e", marginTop: 2 },
  error: { color: "#FF6B6B" },
  historyItem: { backgroundColor: "#fff", borderRadius: 12, padding: 12, borderWidth: 1, borderColor: "#1D2B44" },
  historyAction: { color: "#0c0d0e", fontWeight: "800", marginBottom: 4 },
  historyMeta: { color: "#0c0d0e", lineHeight: 18 },
  scrollContent: { paddingBottom: 24, gap: 12 },
});

import React, { useEffect } from "react";
import { View, Text, FlatList, StyleSheet } from "react-native";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { loadDevices } from "../state/slices/devicesSlice";
import { loadAlerts } from "../state/slices/alertsSlice";
import Icon from "react-native-vector-icons/Feather";
import { api } from "../api/client";

function DeviceRow({
  name,
  lastSeen,
  warn
}: {
  name: string;
  lastSeen: string;
  warn?: boolean;
}) {
  return (
    <View style={styles.deviceBubble}>
      <Icon name="wifi" size={18} color="#8FA0B5" />
      <View style={{ flex: 1 }}>
        <Text style={styles.deviceName}>{name}</Text>
        <Text style={styles.deviceLast}>Last seen: {lastSeen}</Text>
      </View>
      {warn ? <Icon name="alert-octagon" size={18} color="#FF4D4D" /> : null}
    </View>
  );
}

export default function DashboardScreen() {
  const dispatch = useDispatch<AppDispatch>();
  const devices = useSelector((s: RootState) => s.devices.items);
  const alerts = useSelector((s: RootState) => s.alerts.items);

  useEffect(() => {
    dispatch(loadDevices());
    dispatch(loadAlerts());

    api.connectRealtime();
    const unsub = api.subscribe(evt => {
      if (evt?.type === "ALERT_CREATED") dispatch({ type: "alerts/alertReceived", payload: evt.payload });
    });
    return () => {
      unsub();
      api.disconnectRealtime();
    };
  }, [dispatch]);

  return (
    <View style={styles.root}>
      <Text style={styles.sectionTitle}>System Dashboard</Text>

      <View style={styles.systemCard}>
        <View style={styles.systemRow}>
          <Icon name="check-circle" size={20} color="#18E36B" />
          <Text style={styles.systemOnline}>SYSTEM ONLINE</Text>
        </View>
        <Text style={styles.systemSub}>Your network is actively monitored.</Text>
      </View>

      <Text style={styles.sectionTitle}>Detected Devices ({devices.length})</Text>

      <FlatList
        data={devices}
        keyExtractor={(d) => d.id}
        contentContainerStyle={{ gap: 10, paddingBottom: 20 }}
        renderItem={({ item }) => (
          <DeviceRow
            name={item.name}
            lastSeen={new Date(item.lastSeen).toLocaleString()}
            warn={alerts.some(a => a.deviceId === item.id && a.severity === "High")}
          />
        )}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: "#0B1220" },

  sectionTitle: { color: "#fff", fontSize: 16, fontWeight: "800", marginTop: 10, marginBottom: 10 },

  systemCard: {
    backgroundColor: "#0F1A2F",
    borderRadius: 18,
    padding: 16,
    borderWidth: 1,
    borderColor: "#18E36B"
  },
  systemRow: { flexDirection: "row", alignItems: "center", gap: 10, marginBottom: 8 },
  systemOnline: { color: "#18E36B", fontSize: 18, fontWeight: "900" },
  systemSub: { color: "#fff", opacity: 0.9 },

  deviceBubble: {
    backgroundColor: "#0F1A2F",
    borderRadius: 18,
    padding: 14,
    borderWidth: 1,
    borderColor: "#1D2B44",
    flexDirection: "row",
    alignItems: "center",
    gap: 12
  },
  deviceIcon: { fontSize: 18 },
  deviceName: { color: "#fff", fontWeight: "800", fontSize: 15 },
  deviceLast: { color: "#8FA0B5", marginTop: 4, fontSize: 12 },
  warnIcon: { color: "#FF4D4D", fontSize: 18, fontWeight: "900" }
});

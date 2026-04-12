import React, { useEffect, useMemo, useState } from "react";
import { View, Text, ScrollView, StyleSheet, RefreshControl } from "react-native";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { loadDevices } from "../state/slices/devicesSlice";
import { loadAlerts, alertUpsert, alertResolved } from "../state/slices/alertsSlice";
import Icon from "react-native-vector-icons/Feather";
import { api, HealthStatus } from "../api/client";

function MetricCard({ label, value }: { label: string; value: string }) 
{
  return (
    <View style={styles.metricCard}>
      <Text style={styles.metricValue}>{value}</Text>
      <Text style={styles.metricLabel}>{label}</Text>
    </View>
  );
}

export default function DashboardScreen() 
{
  const dispatch = useDispatch<AppDispatch>();
  const devices = useSelector((state: RootState) => state.devices.items);
  const devicesLoading = useSelector((state: RootState) => state.devices.loading);
  const alerts = useSelector((state: RootState) => state.alerts.items);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [manualRefreshing, setManualRefreshing] = useState(false);

  const loadHealth = async (showRefreshSpinner = false) => {
    try {
      if (showRefreshSpinner) 
      {
        setManualRefreshing(true);
      }

      const result = await api.health();
      setHealth(result);
    } 
    catch {
      setHealth(null);
    } 
    finally {
      if (showRefreshSpinner) 
      {
        setManualRefreshing(false);
      }
    }
  };


  useEffect(() => {
    dispatch(loadDevices());
    dispatch(loadAlerts());
    loadHealth();

    const healthTimer = setInterval(() => {
        loadHealth();
      }, 5000);

    api.connectRealtime();
    const unsub = api.subscribe((event) => {

      if (!event)
      {
        return;
      }
      if (event.type === "ALERT_UPSERT") 
      {
        dispatch(alertUpsert(event.payload));
      }

      if (event.type === "ALERT_RESOLVED") 
      {
        dispatch(alertResolved(event.payload));
      }

      if (event.type === "ENFORCEMENT_UPDATED") 
      {
        dispatch(loadDevices());
        loadHealth();
      }
      if (event.type === "WS_EVENT" && event.event === "event.received") 
      {
        dispatch(loadDevices());
      }
    });
    
    return () => {
      clearInterval(healthTimer);
      unsub();
      };
    }, [dispatch]);

    let systemState = "offline";

    if (health) 
    {
      if (health.status === "ok") 
      {
        systemState = "online";
      } 
      else 
      {
        systemState = "degraded";
      }
    }

  const activeAlerts = useMemo(() => {
    let count = 0;

    for (let i = 0; i < alerts.length; i++) {
      if (alerts[i].status === "active") {
        count++;
      }
    }

    return count;
  }, [alerts]);

  const highSeverityAlerts = useMemo(() => {
    let count = 0;

    for (let i = 0; i < alerts.length; i++) {
      if (alerts[i].severity === "High" && alerts[i].status === "active") {
        count++;
      }
    }

    return count;
  }, [alerts]);

  const quarantinedDevices = useMemo(() => {
    let count = 0;

    for (let i = 0; i < devices.length; i++) {
      if (devices[i].status === "quarantined") {
        count++;
      }
    }

    return count;
  }, [devices]);

  let systemIconName: "check-circle" | "alert-circle" | "x-circle" = "x-circle";
  let systemIconColor = "#FF4D4D";
  let systemTitleColor = "#FF4D4D";
  let systemTitleText = "SYSTEM OFFLINE";
  let systemSubText = "Network monitoring is offline.";

  if (systemState === "online") 
  {
    systemIconName = "check-circle";
    systemIconColor = "#18E36B";
    systemTitleColor = "#18E36B";
    systemTitleText = "SYSTEM ONLINE";
    systemSubText = "Your network is actively monitored.";
  } 
  else if (systemState === "degraded") 
  {
    systemIconName = "alert-circle";
    systemIconColor = "#FFD166";
    systemTitleColor = "#FFD166";
    systemTitleText = "SYSTEM DEGRADED";
    systemSubText = "Monitoring may be limited.";
  }

  return (
  <ScrollView
      style={styles.root}
      contentContainerStyle={styles.contentContainer}
      refreshControl={
        <RefreshControl
          refreshing={devicesLoading || manualRefreshing}
          onRefresh={() => {
            dispatch(loadDevices());
            dispatch(loadAlerts());
            loadHealth(true);
          }}
        />
      }
    >
      <View style={styles.systemCard}>
        <View style={styles.systemRow}>
        <Icon
          name={systemIconName}
          size={28}
          color={systemIconColor}
        />
      <Text
        style={[
          styles.systemOnline,
          { color: systemTitleColor }
        ]}
      >
        {systemTitleText}
      </Text>
        </View>

      <Text style={styles.systemSub}>
        {systemSubText}
      </Text>
      
      </View>

      <View style={styles.metricsRow}>
        <MetricCard label="Devices" value={String(devices.length)} />
        <MetricCard label="Active Alerts" value={String(activeAlerts)} />
      </View>

      <View style={styles.metricsRow}>
        <MetricCard label="High Alerts" value={String(highSeverityAlerts)} />
        <MetricCard label="Quarantined" value={String(quarantinedDevices)} />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#c4c4cc" },
  contentContainer: { padding: 16, paddingBottom: 28 },
  sectionTitle: { color: "#fff", fontSize: 16, fontWeight: "800", marginTop: 10, marginBottom: 12 },
  systemCard: { backgroundColor: "#fff", borderRadius: 22, paddingHorizontal: 20, paddingVertical: 28, borderWidth: 1, borderColor: "#fff", marginBottom: 22 },
  systemRow: { flexDirection: "row", alignItems: "center", gap: 14, marginBottom: 10 },
  systemOnline: { fontSize: 26, fontWeight: "900" },
  systemSub: { color: "#0c0d0e", opacity: 0.9, fontSize: 16 },
  systemMeta: { color: "#0c0d0e", marginTop: 8, fontSize: 12 },
  metricsRow: { flexDirection: "row", gap: 10, marginBottom: 12 },
  metricCard: { flex: 1, backgroundColor: "#fff", borderRadius: 16, padding: 14,  borderWidth: 1, borderColor: "#fff", alignItems: "center" },
  metricValue: { color: "#0c0d0e", fontSize: 22, fontWeight: "900" },
  metricLabel: { color: "#0c0d0e", marginTop: 6, fontSize: 12, fontWeight: "700" },
});

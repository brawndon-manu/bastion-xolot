import React, { useEffect, useMemo, useState } from "react";
import { View, Text, ScrollView, StyleSheet, RefreshControl, Image } from "react-native";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { loadDevices } from "../state/slices/devicesSlice";
import { loadAlerts, alertUpsert, alertResolved } from "../state/slices/alertsSlice";
import Icon from "react-native-vector-icons/Feather";
import { api, HealthStatus } from "../api/client";
import { T } from "../theme";

/**
 * Aztec step-crenellation border — pyramid battlement silhouette in gold.
 * Alternating tall/short columns evoke the stepped temple profile.
 */
function AztecStepBorder({ color = T.gold }: { color?: string }) {
  return (
    <View style={{ flexDirection: "row", height: 10, marginBottom: 20 }}>
      {Array.from({ length: 28 }, (_, i) => (
        <View
          key={i}
          style={{
            flex: 1,
            height: i % 2 === 0 ? 10 : 5,
            backgroundColor: color,
            opacity: 0.65,
            alignSelf: "flex-end",
          }}
        />
      ))}
    </View>
  );
}

/**
 * Apple Health-style metric tile: huge coloured number, muted label below.
 * Coloured top border signals the metric's category at a glance.
 */
function MetricCard({ label, value, accent }: { label: string; value: string; accent: string }) {
  return (
    <View style={[styles.metricCard, { borderTopColor: accent, borderTopWidth: 2 }]}>
      <Text style={[styles.metricValue, { color: accent }]}>{value}</Text>
      <Text style={styles.metricLabel}>{label}</Text>
    </View>
  );
}

export default function DashboardScreen() {
  const dispatch = useDispatch<AppDispatch>();
  const devices = useSelector((state: RootState) => state.devices.items);
  const devicesLoading = useSelector((state: RootState) => state.devices.loading);
  const alerts = useSelector((state: RootState) => state.alerts.items);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [manualRefreshing, setManualRefreshing] = useState(false);

  const loadHealth = async (showSpinner = false) => {
    try {
      if (showSpinner) setManualRefreshing(true);
      setHealth(await api.health());
    } catch {
      setHealth(null);
    } finally {
      if (showSpinner) setManualRefreshing(false);
    }
  };

  useEffect(() => {
    dispatch(loadDevices());
    dispatch(loadAlerts());
    loadHealth();
    const healthTimer = setInterval(loadHealth, 5000);
    api.connectRealtime();
    const unsub = api.subscribe((event) => {
      if (!event) return;
      if (event.type === "ALERT_UPSERT")        dispatch(alertUpsert(event.payload));
      if (event.type === "ALERT_RESOLVED")      dispatch(alertResolved(event.payload));
      if (event.type === "ENFORCEMENT_UPDATED") { dispatch(loadDevices()); loadHealth(); }
      if (event.type === "WS_EVENT" && event.event === "event.received") dispatch(loadDevices());
    });
    return () => { clearInterval(healthTimer); unsub(); };
  }, [dispatch]);

  const systemState = health ? (health.status === "ok" ? "online" : "degraded") : "offline";

  const activeAlerts = useMemo(() => alerts.filter((a) => a.status === "active").length, [alerts]);
  const highAlerts   = useMemo(() => alerts.filter((a) => a.severity === "High" && a.status === "active").length, [alerts]);
  const quarantined  = useMemo(() => devices.filter((d) => d.status === "quarantined").length, [devices]);

  // Status visual config
  let iconName: "alert-circle" | "x-circle" | null = "x-circle";
  let iconColor  = T.danger;
  let titleColor = T.dangerText;
  let titleText  = "SYSTEM OFFLINE";
  let subText    = "Network monitoring is offline.";
  let stepColor  = T.danger;

  if (systemState === "online") {
    iconName   = null;
    iconColor  = T.jade;
    titleColor = T.jadeText;
    titleText  = "SYSTEM ONLINE";
    subText    = "Your network is actively monitored.";
    stepColor  = T.gold;
  } else if (systemState === "degraded") {
    iconName   = "alert-circle";
    iconColor  = T.warning;
    titleColor = T.warningText;
    titleText  = "SYSTEM DEGRADED";
    subText    = "Monitoring may be limited.";
    stepColor  = T.warning;
  }

  return (
    <View style={styles.root}>
    <ScrollView
      style={styles.scrollView}
      contentContainerStyle={styles.content}
      refreshControl={
        <RefreshControl
          tintColor={T.jade}
          refreshing={devicesLoading || manualRefreshing}
          onRefresh={() => {
            dispatch(loadDevices());
            dispatch(loadAlerts());
            loadHealth(true);
          }}
        />
      }
    >
      {/* ── System Status Card ─────────────────────────── */}
      <View style={styles.systemCard}>
        <AztecStepBorder color={stepColor} />
        <View style={styles.statusRow}>
          {iconName === null ? (
            <Image
              source={require("../assets/device_online_icon.png")}
              style={{ width: 28, height: 28, tintColor: iconColor }}
              resizeMode="contain"
            />
          ) : (
            <Icon name={iconName} size={28} color={iconColor} />
          )}
          <Text style={[styles.statusTitle, { color: titleColor }]}>{titleText}</Text>
        </View>
        <Text style={styles.statusSub}>{subText}</Text>
      </View>

      {/* ── Metrics ────────────────────────────────────── */}
      <Text style={styles.sectionLabel}>NETWORK OVERVIEW</Text>
      <View style={styles.grid}>
        <MetricCard label="DEVICES"        value={String(devices.length)} accent={T.jadeText} />
        <MetricCard label="ACTIVE ALERTS"  value={String(activeAlerts)}  accent={activeAlerts > 0 ? T.warningText : T.jadeText} />
        <MetricCard label="HIGH SEVERITY"  value={String(highAlerts)}    accent={highAlerts > 0 ? T.dangerText : T.jadeText} />
        <MetricCard label="QUARANTINED"    value={String(quarantined)}   accent={quarantined > 0 ? T.dangerText : T.jadeText} />
      </View>

      <Image
        source={require("../assets/OllinBX.png")}
        style={styles.ollinArt}
        resizeMode="contain"
      />
    </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: T.bgBase },
  scrollView: { flex: 1 },
  content: { padding: 16, paddingBottom: 40 },

  systemCard: {
    backgroundColor: T.bgCard,
    borderRadius: 20,
    paddingHorizontal: 20,
    paddingTop: 20,
    paddingBottom: 24,
    marginBottom: 28,
    elevation: 8,
    shadowColor: T.gold,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.15,
    shadowRadius: 12,
  },
  statusRow: { flexDirection: "row", alignItems: "center", gap: 14, marginBottom: 10 },
  statusTitle: { fontSize: 22, fontWeight: "900", letterSpacing: 1 },
  statusSub: { color: T.textSecondary, fontSize: 15, lineHeight: 22 },

  sectionLabel: {
    color: T.textMuted,
    fontSize: 12,
    fontWeight: "700",
    letterSpacing: 1.5,
    marginBottom: 12,
  },
  grid: { flexDirection: "row", flexWrap: "wrap", gap: 10 },
  metricCard: {
    width: "47.5%",
    backgroundColor: T.bgCard,
    borderRadius: 18,
    paddingVertical: 20,
    paddingHorizontal: 16,
    elevation: 4,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
  },
  metricValue: { fontSize: 52, fontWeight: "700", lineHeight: 58 },
  metricLabel: {
    color: T.textMuted,
    fontSize: 11,
    fontWeight: "700",
    letterSpacing: 1.2,
    marginTop: 6,
  },
  ollinArt: {
    width: "100%",
    height: 260,
    marginTop: 24,
    opacity: 1,
  },
});

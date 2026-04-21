import React, { useEffect, useState } from "react";
import { View, Text, StyleSheet, Switch, ScrollView, Pressable, Alert } from "react-native";
import { useDispatch, useSelector } from "react-redux";
import { RootState, AppDispatch } from "../state/store";
import { setMonitorOnly } from "../state/slices/settingsSlice";
import { loadDevices } from "../state/slices/devicesSlice";
import { api, EnforcementAction, HealthStatus } from "../api/client";
import { T } from "../theme";

export default function ControlsScreen() {
  const dispatch = useDispatch<AppDispatch>();
  const monitorOnly = useSelector((state: RootState) => state.settings.monitorOnly);
  const devices = useSelector((state: RootState) => state.devices.items);
  const [history, setHistory] = useState<EnforcementAction[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const quarantinedDevices = devices.filter((d) => d.status === "quarantined");
  const [releasing, setReleasing] = useState<string | null>(null);

  const handleRelease = (deviceId: string, deviceName: string) => {
    Alert.alert(
      "Release Device",
      `Remove ${deviceName} from quarantine?`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Release",
          onPress: async () => {
            setReleasing(deviceId);
            try {
              await api.unquarantineDevice(deviceId);
              dispatch(loadDevices());
              loadHistory();
            } catch {
              Alert.alert("Error", "Failed to release device.");
            } finally {
              setReleasing(null);
            }
          },
        },
      ]
    );
  };

  const loadHistory = async () => {
    try {
      setError(null);
      setHistory(await api.getEnforcementHistory());
    } catch (e: any) {
      setError(e?.message ?? "Failed to load enforcement history");
    }
  };

  const loadHealth = async () => {
    try {
      const result = await api.health();
      setHealth(result);
      dispatch(setMonitorOnly(result.monitor_only));
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    dispatch(loadDevices());
    loadHistory();
    loadHealth();

    api.connectRealtime();
    const unsub = api.subscribe((event) => {
      if (event && event.type === "ENFORCEMENT_UPDATED") {
        dispatch(loadDevices());
        loadHistory();
        loadHealth();
      }
    });

    return () => { unsub(); api.disconnectRealtime(); };
  }, [dispatch]);

  let backendModeText = "Unable to read backend health right now.";
  let thresholdText: string | null = null;
  if (health) {
    backendModeText = health.monitor_only ? "Backend mode: enabled" : "Backend mode: disabled";
    thresholdText = `Auto-quarantine threshold: ${health.auto_quarantine_threshold}`;
  }

  return (
    <ScrollView style={styles.root} contentContainerStyle={styles.scrollContent}>

      {/* ── Monitor-only toggle ── */}
      <Text style={styles.sectionLabel}>ENFORCEMENT MODE</Text>
      <View style={styles.card}>
        <View style={styles.switchRow}>
          <View style={{ flex: 1 }}>
            <Text style={styles.cardTitle}>Monitor-Only Mode</Text>
            <Text style={styles.note}>{backendModeText}</Text>
            {thresholdText && <Text style={styles.note}>{thresholdText}</Text>}
          </View>
          <Switch
            value={monitorOnly}
            thumbColor={monitorOnly ? T.jade : T.textMuted}
            trackColor={{ false: T.borderSubtle, true: T.borderJade }}
            onValueChange={async (value) => {
              dispatch(setMonitorOnly(value));
              try { await api.setMonitorOnly(value); } catch { /* ignore */ }
              await loadHealth();
            }}
          />
        </View>
      </View>

      {/* ── Quarantined devices ── */}
      <Text style={styles.sectionLabel}>QUARANTINED DEVICES</Text>
      <View style={styles.card}>
        {quarantinedDevices.length === 0 ? (
          <Text style={styles.empty}>No quarantined devices.</Text>
        ) : (
          quarantinedDevices.map((device) => (
            <View key={device.id} style={styles.deviceRow}>
              <View style={{ flex: 1 }}>
                <Text style={styles.deviceName}>{device.name}</Text>
                <Text style={styles.deviceMeta}>Risk score: {device.riskScore}</Text>
                <Text style={styles.deviceMeta}>{device.ip !== "—" ? device.ip : device.mac}</Text>
              </View>
              <Pressable
                style={[styles.releaseBtn, releasing === device.id && styles.releaseBtnDisabled]}
                onPress={() => handleRelease(device.id, device.name)}
                disabled={releasing === device.id}
              >
                <Text style={styles.releaseBtnText}>
                  {releasing === device.id ? "Releasing…" : "Release"}
                </Text>
              </Pressable>
            </View>
          ))
        )}
      </View>

      {/* ── Enforcement history ── */}
      <Text style={styles.sectionLabel}>ENFORCEMENT HISTORY</Text>
      <View style={styles.card}>
        {error && <Text style={styles.error}>{error}</Text>}

        {history.length === 0 && !error && (
          <Text style={styles.empty}>No enforcement actions yet.</Text>
        )}

        {history.map((item) => (
          <View key={item.id} style={styles.historyItem}>
            {/* Aztec accent stripe */}
            <View style={styles.historyStripe} />
            <View style={styles.historyContent}>
              <Text style={styles.historyAction}>
                {item.action.toUpperCase()}
              </Text>
              <Text style={styles.historyDevice}>{item.deviceId}</Text>
              <Text style={styles.historyMeta}>Reason: {item.reason}</Text>
              <Text style={styles.historyMeta}>By: {item.initiatedBy}  ·  Mode: {item.mode}</Text>
              <Text style={styles.historyMeta}>Status: {item.status}</Text>
              {item.evidence && <Text style={styles.historyMeta}>Evidence: present</Text>}
              <Text style={styles.historyTime}>
                {new Date(item.timestamp).toLocaleString()}
              </Text>
            </View>
          </View>
        ))}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: T.bgBase },
  scrollContent: { padding: 16, paddingBottom: 40, gap: 0 },

  sectionLabel: {
    color: T.textGold,
    fontSize: 11,
    fontWeight: "800",
    letterSpacing: 2.5,
    marginTop: 20,
    marginBottom: 10,
  },
  card: {
    backgroundColor: T.bgCard,
    borderRadius: 18,
    padding: 16,
    borderWidth: 1,
    borderColor: T.borderSubtle,
  },
  cardTitle: {
    color: T.textPrimary,
    fontWeight: "700",
    fontSize: 15,
    marginBottom: 4,
  },
  switchRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 12,
  },
  note: {
    color: T.textSecondary,
    fontSize: 13,
    marginTop: 4,
    lineHeight: 18,
  },
  empty: {
    color: T.textMuted,
    fontSize: 14,
    letterSpacing: 0.3,
  },
  error: { color: T.dangerText, fontSize: 13, marginBottom: 8 },

  // Quarantined device row
  deviceRow: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: T.borderSubtle,
    gap: 12,
  },
  deviceName: {
    color: T.textPrimary,
    fontWeight: "700",
    fontSize: 14,
    marginBottom: 2,
  },
  deviceMeta: {
    color: T.textSecondary,
    fontSize: 13,
    marginTop: 1,
  },
  releaseBtn: {
    backgroundColor: T.pillOkBg,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: T.borderJade,
    paddingHorizontal: 14,
    paddingVertical: 8,
  },
  releaseBtnDisabled: {
    opacity: 0.5,
  },
  releaseBtnText: {
    color: T.jadeText,
    fontWeight: "700",
    fontSize: 13,
  },

  // History item
  historyItem: {
    flexDirection: "row",
    gap: 12,
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: T.borderSubtle,
  },
  historyStripe: {
    width: 3,
    borderRadius: 2,
    backgroundColor: T.gold,
    opacity: 0.6,
    alignSelf: "stretch",
  },
  historyContent: { flex: 1 },
  historyAction: {
    color: T.jadeText,
    fontWeight: "800",
    fontSize: 13,
    letterSpacing: 1,
    marginBottom: 2,
  },
  historyDevice: {
    color: T.textPrimary,
    fontWeight: "600",
    fontSize: 13,
    marginBottom: 4,
  },
  historyMeta: {
    color: T.textSecondary,
    fontSize: 12,
    lineHeight: 18,
  },
  historyTime: {
    color: T.textMuted,
    fontSize: 11,
    marginTop: 4,
  },
});

import React, { useEffect, useState } from "react";
import { View, Text, StyleSheet, Pressable, Alert, ScrollView, TextInput } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { selectDeviceById, selectNickname, loadDevices, setNickname } from "../state/slices/devicesSlice";
import StatusPill from "../components/StatusPill";
import { api } from "../api/client";
import { T } from "../theme";

type Props = NativeStackScreenProps<RootStackParamList, "DeviceDetail">;

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue}>{value}</Text>
    </View>
  );
}

export default function DeviceDetailScreen({ route }: Props) {
  const dispatch = useDispatch<AppDispatch>();
  const device = useSelector((state: RootState) =>
    selectDeviceById(state, route.params.deviceId)
  );
  const nickname = useSelector((state: RootState) => selectNickname(state, route.params.deviceId));
  const [busy, setBusy] = useState(false);
  const [editingName, setEditingName] = useState(false);
  const [nameInput, setNameInput] = useState("");

  useEffect(() => {
    if (!device) dispatch(loadDevices());
  }, [dispatch, device]);

  const onQuarantine = async () => {
    if (!device) return;
    try {
      setBusy(true);
      await api.quarantineDevice(device.id, "manual_quarantine");
      await dispatch(loadDevices());
      Alert.alert("Success", "Device quarantined.");
    } catch (error: any) {
      Alert.alert("Error", error?.message ?? "Failed to quarantine device.");
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
    } catch (error: any) {
      Alert.alert("Error", error?.message ?? "Failed to release device.");
    } finally {
      setBusy(false);
    }
  };

  if (!device) {
    return (
      <View style={styles.root}>
        <Text style={styles.loading}>Loading…</Text>
      </View>
    );
  }

  const quarantined = device.status === "quarantined";
  const actionLabel = busy
    ? "Working…"
    : quarantined
    ? "Release Device"
    : "Quarantine Device";
  const actionStyle = quarantined ? styles.releaseBtn : styles.quarantineBtn;

  return (
    <ScrollView style={styles.root} contentContainerStyle={styles.scrollContent}>
      {/* Header */}
      <Text style={styles.title}>{device.name}</Text>

      <View style={styles.statusRow}>
        <Text style={styles.statusLabel}>Behavioral Status</Text>
        <StatusPill status={(device.status as "normal" | "quarantined") || "normal"} />
      </View>

      {/* Name */}
      <Text style={styles.sectionLabel}>DEVICE NAME</Text>
      <View style={styles.card}>
        {editingName ? (
          <View style={styles.nameEditRow}>
            <TextInput
              style={styles.nameInput}
              value={nameInput}
              onChangeText={setNameInput}
              placeholder="Enter a name…"
              placeholderTextColor={T.textMuted}
              autoFocus
            />
            <Pressable
              style={styles.saveBtn}
              onPress={() => {
                dispatch(setNickname({ deviceId: device.id, nickname: nameInput }));
                setEditingName(false);
              }}
            >
              <Text style={styles.saveBtnText}>Save</Text>
            </Pressable>
            <Pressable onPress={() => setEditingName(false)} style={styles.cancelBtn}>
              <Text style={styles.cancelBtnText}>Cancel</Text>
            </Pressable>
          </View>
        ) : (
          <Pressable
            style={styles.nameRow}
            onPress={() => { setNameInput(nickname ?? ""); setEditingName(true); }}
          >
            <Text style={styles.nameDisplay}>
              {nickname ?? "Tap to give this device a name"}
            </Text>
            <Text style={styles.editHint}>{nickname ? "Edit" : "+"}</Text>
          </Pressable>
        )}
      </View>

      {/* Info card */}
      <Text style={styles.sectionLabel}>DEVICE INFO</Text>
      <View style={styles.card}>
        <Row label="IP Address" value={device.ip} />
        <View style={styles.divider} />
        <Row label="MAC Address" value={device.mac} />
        <View style={styles.divider} />
        <Row label="Hostname" value={device.hostname ?? "—"} />
        <View style={styles.divider} />
        <Row label="First Seen" value={device.firstSeen} />
        <View style={styles.divider} />
        <Row label="Last Seen" value={device.lastSeen} />
        <View style={styles.divider} />
        <Row label="Risk Score" value={String(device.riskScore)} />
        <View style={styles.divider} />
        <Row label="Status" value={device.status} />
      </View>

      {/* Action button */}
      <Pressable
        style={[styles.actionBtn, actionStyle, busy && styles.btnDisabled]}
        onPress={quarantined ? onRelease : onQuarantine}
        disabled={busy}
      >
        <Text style={styles.actionBtnText}>{actionLabel}</Text>
      </Pressable>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: T.bgBase },
  scrollContent: { padding: 16, paddingBottom: 40 },
  loading: { color: T.textSecondary, margin: 24 },

  title: {
    color: T.textPrimary,
    fontSize: 24,
    fontWeight: "800",
    marginBottom: 12,
    letterSpacing: 0.3,
  },
  statusRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 24,
  },
  statusLabel: {
    color: T.textSecondary,
    fontWeight: "600",
    fontSize: 14,
    letterSpacing: 0.5,
  },

  sectionLabel: {
    color: T.textGold,
    fontSize: 11,
    fontWeight: "800",
    letterSpacing: 2.5,
    marginBottom: 10,
  },
  card: {
    backgroundColor: T.bgCard,
    borderRadius: 18,
    paddingVertical: 4,
    paddingHorizontal: 16,
    borderWidth: 1,
    borderColor: T.borderSubtle,
    marginBottom: 24,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    gap: 12,
    paddingVertical: 13,
  },
  rowLabel: {
    color: T.textSecondary,
    fontSize: 14,
    letterSpacing: 0.3,
  },
  rowValue: {
    color: T.textPrimary,
    fontSize: 14,
    fontWeight: "600",
    flexShrink: 1,
    textAlign: "right",
  },
  divider: {
    height: 1,
    backgroundColor: T.borderSubtle,
  },

  nameRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 14,
    paddingHorizontal: 16,
  },
  nameDisplay: { color: T.textPrimary, fontSize: 15, fontWeight: "600", flex: 1 },
  editHint: { color: T.gold, fontWeight: "700", fontSize: 14 },
  nameEditRow: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 10,
    paddingHorizontal: 12,
    gap: 8,
  },
  nameInput: {
    flex: 1,
    color: T.textPrimary,
    backgroundColor: T.bgBase,
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 8,
    fontSize: 15,
    borderWidth: 1,
    borderColor: T.borderSubtle,
  },
  saveBtn: {
    backgroundColor: T.jade,
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 8,
  },
  saveBtnText: { color: "#000", fontWeight: "800", fontSize: 13 },
  cancelBtn: { paddingHorizontal: 8, paddingVertical: 8 },
  cancelBtnText: { color: T.textMuted, fontSize: 13 },

  // Action button
  actionBtn: {
    borderRadius: 16,
    paddingVertical: 16,
    alignItems: "center",
    borderWidth: 1,
  },
  quarantineBtn: {
    backgroundColor: T.pillBadBg,
    borderColor: T.borderDanger,
  },
  releaseBtn: {
    backgroundColor: T.pillOkBg,
    borderColor: T.borderJade,
  },
  btnDisabled: { opacity: 0.5 },
  actionBtnText: {
    color: T.textPrimary,
    fontWeight: "800",
    fontSize: 15,
    letterSpacing: 0.5,
  },
});

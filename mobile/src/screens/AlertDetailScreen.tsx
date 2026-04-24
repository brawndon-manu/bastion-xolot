import React, { useEffect, useState } from "react";
import { View, Text, StyleSheet, ScrollView, Pressable, Alert } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { selectAlertById, loadAlerts, alertResolved } from "../state/slices/alertsSlice";
import { selectDeviceById, selectNickname, loadDevices } from "../state/slices/devicesSlice";
import { TranslationLevel } from "../state/slices/settingsSlice";
import Icon from "react-native-vector-icons/Feather";
import PlainEnglishPanel from "../components/PlainEnglishPanel";
import { api } from "../api/client";
import { T } from "../theme";

type Props = NativeStackScreenProps<RootStackParamList, "AlertDetail">;

function Section({ title, body }: { title: string; body: string }) {
  return (
    <View style={styles.sectionBox}>
      <Text style={styles.sectionHeader}>{title}</Text>
      <Text style={styles.sectionBody}>{body}</Text>
    </View>
  );
}

export default function AlertDetailScreen({ route }: Props) {
  const dispatch = useDispatch<AppDispatch>();
  const alert = useSelector((state: RootState) =>
    selectAlertById(state, route.params.alertId)
  );
  const translationLevel = useSelector((state: RootState) =>
    state.settings.translationLevel as TranslationLevel
  );
  const [resolving, setResolving] = useState(false);
  const [explanation, setExplanation] = useState<string | null>(null);
  const device = useSelector((state: RootState) =>
    alert ? selectDeviceById(state, alert.deviceId) : undefined
  );
  const nickname = useSelector((state: RootState) =>
    alert ? selectNickname(state, alert.deviceId) : null
  );

  useEffect(() => {
    if (!alert) dispatch(loadAlerts());
  }, [dispatch, alert]);

  useEffect(() => {
    if (alert && !device) dispatch(loadDevices());
  }, [dispatch, alert, device]);

  useEffect(() => {
    if (!alert || alert.status === "resolved") return;
    api.getAlertExplanation(alert.id, translationLevel)
      .then(setExplanation)
      .catch(() => setExplanation(null));
  }, [alert?.id, alert?.status, translationLevel]);

  const onResolve = async () => {
    if (!alert || alert.status === "resolved") return;
    try {
      setResolving(true);
      const resolved = await api.resolveAlert(alert.id);
      dispatch(alertResolved(resolved));
    } catch (err: any) {
      Alert.alert("Error", err?.message ?? "Failed to resolve alert.");
    } finally {
      setResolving(false);
    }
  };

  if (!alert) {
    return (
      <View style={styles.root}>
        <Text style={{ color: T.textSecondary }}>Loading…</Text>
      </View>
    );
  }

  // Severity config
  const isHigh = alert.severity === "High";
  const isMed  = alert.severity === "Medium";

  let borderColor = T.borderTurquoise;
  let titleColor  = T.turquoiseText;
  let titleText   = alert.severity.toUpperCase() + " ALERT";
  let alertIcon   = null;

  if (isHigh) {
    borderColor = T.borderDanger;
    titleColor  = T.dangerText;
    titleText   = "HIGH SEVERITY ALERT";
    alertIcon   = <Icon name="alert-circle" size={18} color={T.danger} />;
  } else if (isMed) {
    borderColor = T.borderWarning;
    titleColor  = T.warningText;
  }

  // Evidence text
  let evidenceText = "No supporting evidence provided.";
  if (alert.evidence.length > 0) {
    evidenceText = alert.evidence.map((e) => "◆  " + e).join("\n");
  }

  // Recommended action
  let recommendedAction = "Review the affected device and verify the activity is expected.";
  if (alert.type === "ids_alert") {
    recommendedAction =
      "Inspect the affected device and review the IDS signature evidence before deciding on quarantine or release.";
  } else if (alert.type === "correlated_threat") {
    recommendedAction =
      "Multiple signals agree this may be a real threat. Review evidence carefully and consider containment immediately.";
  } else if (alert.type === "behavioral_anomaly") {
    recommendedAction =
      "Compare this behavior against the device's normal role on the network and investigate any unexplained changes.";
  } else if (alert.type === "dns_block") {
    recommendedAction =
      "Review the blocked domain request and confirm whether the destination should be allowed or investigated.";
  }

  return (
    <ScrollView style={styles.root} contentContainerStyle={styles.scrollContent}>
      {/* Severity header card */}
      <View style={[styles.topCard, { borderColor }]}>
        <View style={styles.topCardRow}>
          {alertIcon}
          <Text style={[styles.sevTitle, { color: titleColor }]}>{titleText}</Text>
        </View>
        <Text style={styles.sevSubtitle}>{alert.title}</Text>
      </View>

      <Section title="ALERT SOURCE" body={alert.sourceLabel} />
      {device && (
        <Section
          title="DEVICE"
          body={[
            nickname ? nickname : device.name,
            "IP: " + device.ip,
            "MAC: " + device.mac,
          ].join("\n")}
        />
      )}
      <PlainEnglishPanel text={explanation ?? alert.plainEnglish} />
      <Section title="CORRELATION / SUPPORTING EVIDENCE" body={evidenceText} />
      <Section title="RECOMMENDED ACTION" body={recommendedAction} />
      <Section title="TIMESTAMP" body={new Date(alert.timestamp).toLocaleString()} />

      {alert.confidence !== null && (
        <Section
          title="DETECTION CONFIDENCE"
          body={Math.round(alert.confidence * 100) + "%"}
        />
      )}

      {alert.status === "resolved" ? (
        <View style={styles.resolvedBadge}>
          <Icon name="check-circle" size={16} color={T.jadeText} />
          <Text style={styles.resolvedText}>Resolved</Text>
        </View>
      ) : (
        <Pressable
          style={[styles.resolveBtn, resolving && styles.btnDisabled]}
          onPress={onResolve}
          disabled={resolving}
        >
          <Text style={styles.resolveBtnText}>
            {resolving ? "Resolving…" : "Mark as Resolved"}
          </Text>
        </Pressable>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: T.bgBase },
  scrollContent: { padding: 16, paddingBottom: 32 },

  // Top severity card
  topCard: {
    backgroundColor: T.bgCard,
    borderRadius: 20,
    padding: 18,
    borderWidth: 1.5,
    marginBottom: 12,
  },
  topCardRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
    marginBottom: 10,
  },
  sevTitle: {
    fontWeight: "900",
    fontSize: 14,
    letterSpacing: 1.5,
  },
  sevSubtitle: {
    color: T.textPrimary,
    fontSize: 15,
    lineHeight: 22,
    fontWeight: "500",
  },

  // Generic section
  sectionBox: {
    backgroundColor: T.bgCard,
    borderRadius: 18,
    padding: 16,
    borderWidth: 1,
    borderColor: T.borderSubtle,
    marginBottom: 10,
  },
  sectionHeader: {
    color: T.textGold,
    fontWeight: "800",
    fontSize: 11,
    letterSpacing: 2,
    marginBottom: 10,
  },
  sectionBody: {
    color: T.textPrimary,
    lineHeight: 22,
    fontSize: 14,
  },
  resolveBtn: {
    marginTop: 8,
    backgroundColor: T.bgCard,
    borderRadius: 16,
    paddingVertical: 16,
    alignItems: "center",
    borderWidth: 1,
    borderColor: T.borderJade,
  },
  resolveBtnText: {
    color: T.jadeText,
    fontWeight: "800",
    fontSize: 15,
    letterSpacing: 0.5,
  },
  btnDisabled: { opacity: 0.5 },
  resolvedBadge: {
    marginTop: 8,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    paddingVertical: 14,
    backgroundColor: T.pillOkBg,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: T.borderJade,
  },
  resolvedText: {
    color: T.jadeText,
    fontWeight: "800",
    fontSize: 15,
  },
});

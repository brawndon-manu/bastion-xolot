import React, { useEffect } from "react";
import { View, Text, StyleSheet, ScrollView } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { selectAlertById, loadAlerts } from "../state/slices/alertsSlice";
import Icon from "react-native-vector-icons/Feather";
import PlainEnglishPanel from "../components/PlainEnglishPanel";
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

  useEffect(() => {
    if (!alert) dispatch(loadAlerts());
  }, [dispatch, alert]);

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
      <PlainEnglishPanel text={alert.plainEnglish} />
      <Section title="CORRELATION / SUPPORTING EVIDENCE" body={evidenceText} />
      <Section title="RECOMMENDED ACTION" body={recommendedAction} />
      <Section title="TIMESTAMP" body={new Date(alert.timestamp).toLocaleString()} />

      {alert.confidence !== null && (
        <Section
          title="DETECTION CONFIDENCE"
          body={Math.round(alert.confidence * 100) + "%"}
        />
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
});

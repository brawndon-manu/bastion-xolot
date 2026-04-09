import React, { useEffect } from "react";
import { View, Text, StyleSheet, ScrollView } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { selectAlertById, loadAlerts } from "../state/slices/alertsSlice";
import Icon from "react-native-vector-icons/Feather";

type Props = NativeStackScreenProps<RootStackParamList, "AlertDetail">;

function Section({ title, body }: { title: string; body: string }) 
{
  return (
    <View style={styles.sectionBox}>
      <Text style={styles.sectionHeader}>{title}</Text>
      <Text style={styles.sectionBody}>{body}</Text>
    </View>
  );
}

export default function AlertDetailScreen({ route }: Props) 
{
  const dispatch = useDispatch<AppDispatch>();
  const alert = useSelector((state: RootState) => selectAlertById(state, route.params.alertId));

  useEffect(() => {
    if (!alert)
    {
      dispatch(loadAlerts());
    }
  }, [dispatch, alert]);

  if (!alert) 
  {
    return (
      <View style={styles.root}>
        <Text style={{ color: "#fff" }}>Loading…</Text>
      </View>
    );
  }

  const isHigh = alert.severity === "High";

  let topCardStyle = styles.alertTopCardMed;
  let titleStyle = styles.sevMed;
  let titleText = alert.severity.toUpperCase() + " ALERT";
  let alertIcon = null;

  let confidenceSection = null;

  if (isHigh) 
  {
    topCardStyle = styles.alertTopCardHigh;
    titleStyle = styles.sevHigh;
    titleText = "HIGH SEVERITY ALERT";
    alertIcon = <Icon name="alert-circle" size={18} color="#FF4D4D" />;
  }

  if (alert.confidence !== null) 
  {
    confidenceSection = (<Section title="CONFIDENCE" body={ Math.round(alert.confidence * 100) + "%"} />);
  }

  let evidenceText = "No supporting evidence provided.";
  if (alert.evidence.length > 0) 
  {
    let text = "";
    for (let i = 0; i < alert.evidence.length; i++) 
    {
      text += "• " + alert.evidence[i] + "\n";
    }
    evidenceText = text.trimEnd();
  }

  let recommendedAction = "Review the affected device and verify the activity is expected.";
  if (alert.type === "ids_alert") 
  {
    recommendedAction = "Inspect the affected device and review the IDS signature evidence before deciding on quarantine or release.";
  } 
  else if (alert.type === "correlated_threat") 
  {
    recommendedAction = "Multiple signals agree this may be a real threat. Review evidence carefully and consider containment immediately.";
  } 
  else if (alert.type === "behavioral_anomaly") 
  {
    recommendedAction = "Compare this behavior against the device’s normal role on the network and investigate any unexplained changes.";
  } 
  else if (alert.type === "dns_block") 
  {
    recommendedAction = "Review the blocked domain request and confirm whether the destination should be allowed or investigated.";
  }

  return (
    <ScrollView style={styles.root} contentContainerStyle={styles.scrollContent}>
      <View style={[styles.alertTopCard, topCardStyle]}>
      <View style={{ flexDirection: "row", alignItems: "center", gap: 6 }}>
        {alertIcon}
        
      <Text style={[styles.sevTitle, titleStyle]}>
        {titleText}
      </Text>
      </View>
        <Text style={styles.sevSubtitle}>{alert.title}</Text>
      </View>

      <Section title="ALERT SOURCE" body={alert.sourceLabel} />
      <Section title="PLAIN-ENGLISH SUMMARY" body={alert.plainEnglish} />
      <Section title="CORRELATION / SUPPORTING EVIDENCE" body={evidenceText} />
      <Section title="RECOMMENDED ACTION" body={recommendedAction} />
      <Section title="TIMESTAMP" body={new Date(alert.timestamp).toLocaleString()} />

      {confidenceSection}

      </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#0B1220", padding: 16 },
  scrollContent: { padding: 16, paddingBottom: 24 },
  alertTopCard: { backgroundColor: "#0F1A2F", borderRadius: 18, padding: 14, borderWidth: 2, marginBottom: 12 },
  alertTopCardHigh: { borderColor: "#FF4D4D" },
  alertTopCardMed: { borderColor: "#B7892E" },
  sevTitle: { fontWeight: "900", fontSize: 14, marginBottom: 6, letterSpacing: 0.8 },
  sevHigh: { color: "#FF4D4D" },
  sevMed: { color: "#FFD166" },
  sevSubtitle: { color: "#B7C0CC", fontSize: 13 },
  sectionBox: { backgroundColor: "#0F1A2F", borderRadius: 18, padding: 14, borderWidth: 1, borderColor: "#1D2B44", marginBottom: 10 },
  sectionHeader: { color: "#fff", fontWeight: "900", marginBottom: 8, letterSpacing: 0.6 },
  sectionBody: { color: "#B7C0CC", lineHeight: 20 },
});

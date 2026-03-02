import React, { useEffect } from "react";
import { View, Text, StyleSheet, Pressable } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { selectAlertById, loadAlerts } from "../state/slices/alertsSlice";

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
  const alert = useSelector((s: RootState) => selectAlertById(s, route.params.alertId));

  useEffect(() => {
    if (!alert) dispatch(loadAlerts());
  }, [dispatch, alert]);

  if (!alert) {
    return (
      <View style={styles.root}>
        <Text style={{ color: "#fff" }}>Loading…</Text>
      </View>
    );
  }

  const isHigh = alert.severity === "High";

  const whatHappened =
    "An unknown device (manufacturer unknown) is attempting to send a large amount of data to an external server in a foreign country. This activity started recently and is outside this device’s normal behavior.";
  const whyRisk =
    "Potential data theft. This behavior is typical of “data exfiltration.” If this is not a device you authorized, it may indicate a malicious actor attempting to steal sensitive business files or customer information.";
  const statusAction =
    "Bastión Xólot automatically blocked this connection. The device is now isolated from the suspicious server. You must review and take action.";
  const nextSteps =
    "1) Tap QUARANTINE DEVICE to stop all network activity.\n2) Physically inspect the terminal for tampering.\n3) If legitimate, tap RELEASE & UNBLOCK.";

  return (
    <View style={styles.root}>
      <View style={[styles.alertTopCard, isHigh ? styles.alertTopCardHigh : styles.alertTopCardMed]}>
        <Text style={[styles.sevTitle, isHigh ? styles.sevHigh : styles.sevMed]}>
          {isHigh ? "HIGH SEVERITY ALERT" : "ALERT"}
        </Text>
        <Text style={styles.sevSubtitle}>{alert.title}</Text>
      </View>

      <Section title="WHAT HAPPENED" body={whatHappened} />
      <Section title="WHY THIS IS A RISK" body={whyRisk} />
      <Section title="STATUS & ACTION TAKEN" body={statusAction} />
      <Section title="RECOMMENDED NEXT STEPS" body={nextSteps} />

      {/*mockup*/}
      <View style={styles.bottomBar}>
        <Pressable style={[styles.bottomBtn, styles.quarantineBtn]}>
          <Text style={styles.bottomBtnText}>QUARANTINE DEVICE</Text>
        </Pressable>
        <Pressable style={[styles.bottomBtn, styles.releaseBtn]}>
          <Text style={styles.bottomBtnText}>RELEASE & UNBLOCK</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#0B1220", padding: 16, paddingBottom: 92 },

  alertTopCard: {
    backgroundColor: "#0F1A2F",
    borderRadius: 18,
    padding: 14,
    borderWidth: 2,
    marginBottom: 12
  },
  alertTopCardHigh: { borderColor: "#FF4D4D" },
  alertTopCardMed: { borderColor: "#B7892E" },

  sevTitle: { fontWeight: "900", fontSize: 14, marginBottom: 6, letterSpacing: 0.8 },
  sevHigh: { color: "#FF4D4D" },
  sevMed: { color: "#FFD166" },
  sevSubtitle: { color: "#B7C0CC", fontSize: 13 },

  sectionBox: {
    backgroundColor: "#0F1A2F",
    borderRadius: 18,
    padding: 14,
    borderWidth: 1,
    borderColor: "#1D2B44",
    marginBottom: 10
  },
  sectionHeader: { color: "#fff", fontWeight: "900", marginBottom: 8, letterSpacing: 0.6 },
  sectionBody: { color: "#B7C0CC", lineHeight: 20 },

  bottomBar: {
    position: "absolute",
    left: 16,
    right: 16,
    bottom: 16,
    flexDirection: "row",
    gap: 12
  },
  bottomBtn: {
    flex: 1,
    borderRadius: 999,
    paddingVertical: 14,
    alignItems: "center",
    borderWidth: 1
  },
  releaseBtn: { backgroundColor: "#18E36B", borderColor: "#18E36B" },
  quarantineBtn: { backgroundColor: "#FF4D4D", borderColor: "#FF4D4D" },
  bottomBtnText: { color: "#0B1220", fontWeight: "900", letterSpacing: 0.4 }
});

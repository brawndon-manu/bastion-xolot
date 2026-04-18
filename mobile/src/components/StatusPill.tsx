import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { T } from "../theme";

export default function StatusPill({ status }: { status: string }) {
  let label  = "Unknown";
  let bg     = T.pillNeutralBg;
  let border = T.borderTurquoise;
  let color  = T.turquoiseText;

  if (status === "quarantined" || status === "offline") {
    label  = status === "quarantined" ? "Quarantined" : "Offline";
    bg     = T.pillBadBg;
    border = T.borderDanger;
    color  = T.dangerText;
  } else if (status === "warning") {
    label  = "Warning";
    bg     = T.pillWarnBg;
    border = T.borderWarning;
    color  = T.warningText;
  } else if (status === "normal") {
    label  = "Normal";
    bg     = T.pillOkBg;
    border = T.borderJade;
    color  = T.jadeText;
  }

  return (
    <View style={[styles.pill, { backgroundColor: bg, borderColor: border }]}>
      <Text style={[styles.text, { color }]}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  pill: {
    paddingHorizontal: 11,
    paddingVertical: 5,
    borderRadius: 8,
    borderWidth: 1,
  },
  text: { fontSize: 11, fontWeight: "800", letterSpacing: 0.3 },
});

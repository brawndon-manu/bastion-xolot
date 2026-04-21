import React from "react";
import { View, Text, StyleSheet } from "react-native";
import type { Alert } from "../api/client";
import { T } from "../theme";

export default function AlertCard({ alert }: { alert: Alert }) {
  const resolved = alert.status === "resolved";

  let stripe       = resolved ? T.jade : T.turquoise;
  let accentText   = resolved ? T.jadeText : T.turquoiseText;
  let accentBg     = resolved ? T.pillOkBg : T.pillNeutralBg;
  let accentBorder = resolved ? T.borderJade : T.borderTurquoise;

  if (!resolved) {
    if (alert.severity === "High") {
      stripe       = T.danger;
      accentText   = T.dangerText;
      accentBg     = T.pillBadBg;
      accentBorder = T.borderDanger;
    } else if (alert.severity === "Medium") {
      stripe       = T.warning;
      accentText   = T.warningText;
      accentBg     = T.pillWarnBg;
      accentBorder = T.borderWarning;
    }
  }

  return (
    <View style={[styles.card, resolved && styles.cardResolved]}>
      <View style={[styles.stripe, { backgroundColor: stripe }]} />

      <View style={styles.body}>
        <View style={styles.top}>
          <Text style={[styles.title, resolved && styles.titleResolved]} numberOfLines={2}>{alert.title}</Text>
          <View style={[styles.sevBadge, { backgroundColor: accentBg, borderColor: accentBorder }]}>
            <Text style={[styles.sevText, { color: accentText }]}>
              {resolved ? "RESOLVED" : alert.severity.toUpperCase()}
            </Text>
          </View>
        </View>

        <View style={styles.badgeRow}>
          <View style={styles.sourceBadge}>
            <Text style={styles.sourceBadgeText}>{alert.sourceLabel}</Text>
          </View>
          {alert.confidence !== null && (
            <View style={styles.confidenceBadge}>
              <Text style={styles.confidenceText}>
                {Math.round(alert.confidence * 100)}%
              </Text>
            </View>
          )}
        </View>

        <Text style={styles.preview} numberOfLines={2}>{alert.plainEnglish}</Text>
        <Text style={styles.time}>{new Date(alert.timestamp).toLocaleString()}</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: T.bgCard,
    borderRadius: 16,
    flexDirection: "row",
    overflow: "hidden",
    elevation: 4,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 6,
  },
  cardResolved: {
    opacity: 0.55,
  },
  stripe: { width: 4 },
  body: { flex: 1, padding: 14 },
  top: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: 10,
    marginBottom: 10,
  },
  title: { color: T.textPrimary, fontWeight: "700", fontSize: 15, flexShrink: 1, lineHeight: 20 },
  titleResolved: { color: T.textSecondary },
  sevBadge: { paddingHorizontal: 9, paddingVertical: 4, borderRadius: 8, borderWidth: 1 },
  sevText: { fontSize: 10, fontWeight: "800", letterSpacing: 0.8 },

  badgeRow: { flexDirection: "row", gap: 8, marginBottom: 10, flexWrap: "wrap" },
  sourceBadge: {
    backgroundColor: "rgba(201,162,76,0.12)",
    borderRadius: 8,
    paddingHorizontal: 9,
    paddingVertical: 3,
    borderWidth: 1,
    borderColor: T.borderGold,
  },
  sourceBadgeText: { color: T.goldText, fontSize: 10, fontWeight: "700" },
  confidenceBadge: {
    backgroundColor: T.pillOkBg,
    borderRadius: 8,
    paddingHorizontal: 9,
    paddingVertical: 3,
    borderWidth: 1,
    borderColor: T.borderJade,
  },
  confidenceText: { color: T.jadeText, fontSize: 10, fontWeight: "700" },

  preview: { color: T.textSecondary, lineHeight: 20, fontSize: 13 },
  time: { color: T.textMuted, marginTop: 8, fontSize: 11 },
});

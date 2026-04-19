import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { T } from "../theme";

/** AI threat summary — gold step-border panel labelled "XÓLOT SAYS". */

export default function PlainEnglishPanel({ text }: { text: string }) {
  return (
    <View style={styles.panel}>
      {/* Mini Aztec step bar across top */}
      <View style={styles.stepRow}>
        {Array.from({ length: 20 }, (_, i) => (
          <View
            key={i}
            style={{
              flex: 1,
              height: i % 2 === 0 ? 5 : 2,
              backgroundColor: T.gold,
              opacity: 0.55,
              alignSelf: "flex-end",
            }}
          />
        ))}
      </View>

      <View style={styles.inner}>
        <Text style={styles.title}>XÓLOT SAYS</Text>
        <Text style={styles.body}>{text}</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  panel: {
    backgroundColor: T.bgCard,
    borderRadius: 16,
    overflow: "hidden",
    borderWidth: 1,
    borderColor: T.borderGold,
    marginBottom: 10,
    elevation: 4,
    shadowColor: T.gold,
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.15,
    shadowRadius: 8,
  },
  stepRow: { flexDirection: "row", height: 5 },
  inner: { padding: 16 },
  title: {
    color: T.gold,
    fontWeight: "900",
    fontSize: 11,
    letterSpacing: 2.5,
    marginBottom: 10,
  },
  body: { color: T.textPrimary, lineHeight: 22, fontSize: 14 },
});

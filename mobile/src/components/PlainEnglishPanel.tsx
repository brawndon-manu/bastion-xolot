import React from "react";
import { View, Text, StyleSheet } from "react-native";

export default function PlainEnglishPanel({ text }: { text: string }) {
  return (
    <View style={styles.panel}>
      <Text style={styles.title}>Plain-English Summary</Text>
      <Text style={styles.body}>{text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  panel: { backgroundColor: "#0F1A2F", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#223556" },
  title: { color: "#fff", fontWeight: "800", marginBottom: 8 },
  body: { color: "#B7C0CC", lineHeight: 20 }
});

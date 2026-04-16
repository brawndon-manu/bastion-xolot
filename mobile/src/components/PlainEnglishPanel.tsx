import React from "react";
import { View, Text, StyleSheet } from "react-native";

/** */

export default function PlainEnglishPanel({ text }: { text: string }) 
{
  return (
    <View style={styles.panel}>
      <Text style={styles.title}>PLAIN-ENGLISH SUMMARY</Text>
      <Text style={styles.body}>{text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  panel: { backgroundColor: "#fff", borderRadius: 16, padding: 14, borderWidth: 1, borderColor: "#fff", marginBottom: 10 },
  title: { color: "#0c0d0e", fontWeight: "800", marginBottom: 8 },
  body: { color: "#0c0d0e", lineHeight: 20 }
});

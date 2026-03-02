import React from "react";
import { View, Text, StyleSheet, Pressable } from "react-native";
import { useDispatch } from "react-redux";
import { AppDispatch } from "../state/store";
import { signOut } from "../state/slices/authSlice";

export default function SettingsScreen() {
  const dispatch = useDispatch<AppDispatch>();

  return (
    <View style={styles.root}>
      <Text style={styles.muted}>TODO</Text>

      <Pressable style={styles.btn} onPress={() => dispatch(signOut())}>
        <Text style={styles.btnText}>Sign out</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: "#0B1220" },
  title: { color: "#fff", fontSize: 22, fontWeight: "800", marginBottom: 6 },
  muted: { color: "#B7C0CC", marginBottom: 12 },
  btn: { marginTop: 14, backgroundColor: "#2E5BFF", borderRadius: 12, paddingVertical: 12, alignItems: "center" },
  btnText: { color: "#fff", fontWeight: "700" }
});

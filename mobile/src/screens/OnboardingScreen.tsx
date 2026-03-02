import React, { useState } from "react";
import { View, Text, TextInput, Pressable, StyleSheet } from "react-native";
import { useDispatch } from "react-redux";
import { AppDispatch } from "../state/store";
import { pairWithGateway } from "../state/slices/authSlice";

export default function OnboardingScreen() {
  const dispatch = useDispatch<AppDispatch>();
  const [pin, setPin] = useState("1234");
  const [error, setError] = useState<string | null>(null);

  const onPair = async () => {
    setError(null);
    try {
      await dispatch(pairWithGateway(pin)).unwrap();
    } catch (e: any) {
      setError(e?.message ?? "Pairing failed");
    }
  };

  return (
    <View style={styles.root}>
      <Text style={styles.subtitle}>
        Pair your phone with the gateway on your local network
      </Text>

      <View style={styles.card}>
        <Text style={styles.label}>Gateway PIN</Text>
        <TextInput
          value={pin}
          onChangeText={setPin}
          style={styles.input}
          placeholder="Enter PIN"
          placeholderTextColor="#7C889A"
          keyboardType="number-pad"
        />
        {error ? <Text style={styles.error}>{error}</Text> : null}

        <Pressable style={styles.button} onPress={onPair}>
          <Text style={styles.buttonText}>Pair (demo PIN: 1234)</Text>
        </Pressable>

      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 20, backgroundColor: "#0B1220", justifyContent: "center" },
  title: { color: "#fff", fontSize: 34, fontWeight: "800", marginBottom: 8 },
  subtitle: { color: "#B7C0CC", fontSize: 16, marginBottom: 18, lineHeight: 22 },
  card: { backgroundColor: "#111B2E", borderRadius: 16, padding: 16, borderWidth: 1, borderColor: "#1D2B44" },
  label: { color: "#B7C0CC", marginBottom: 8, fontSize: 14 },
  input: {
    backgroundColor: "#0B1220",
    borderRadius: 12,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: "#fff",
    borderWidth: 1,
    borderColor: "#223556"
  },
  button: { marginTop: 14, backgroundColor: "#2E5BFF", borderRadius: 12, paddingVertical: 12, alignItems: "center" },
  buttonText: { color: "#fff", fontWeight: "700" },
  error: { marginTop: 10, color: "#FF6B6B" },
  hint: { marginTop: 12, color: "#8FA0B5", fontSize: 12, lineHeight: 18 }
});

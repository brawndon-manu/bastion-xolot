import React, { useState } from "react";
import { View, Text, TextInput, Pressable, StyleSheet, Image } from "react-native";
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
    } catch {
      setError("Pairing failed");
    }
  };

  return (
    <View style={styles.root}>
      {/* top spacer pushes logo+title to vertical center */}
      <View style={styles.topSpacer} />

      <View style={styles.brandSection}>
        <Image
          source={require("../assets/logo.png")}
          style={styles.logo}
          resizeMode="contain"
        />
        <Text style={styles.title}>BASTIÓN XÓLOT</Text>
        <Text style={styles.tagline}>Guardian of Your Network</Text>
      </View>

      <View style={styles.bottomSpacer} />

      <View style={styles.card}>
        <Text style={styles.cardLabel}>CONNECT TO GATEWAY</Text>
        <Text style={styles.cardTitle}>Enter your pairing PIN</Text>
        <TextInput
          value={pin}
          onChangeText={setPin}
          style={styles.input}
          placeholderTextColor="#7C889A"
          keyboardType="number-pad"
          textAlign="center"
        />
        {error && <Text style={styles.error}>{error}</Text>}
        <Pressable style={styles.button} onPress={onPair}>
          <Text style={styles.buttonText}>Connect</Text>
        </Pressable>
        <Text style={styles.hint}>Demo PIN: 1234</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: "#0a0a0a",
    paddingHorizontal: 24,
    paddingBottom: 40,
  },
  topSpacer: { flex: 1 },
  brandSection: { alignItems: "center" },
  logo: { width: 120, height: 120, marginBottom: 20 },
  title: {
    fontSize: 28,
    fontWeight: "900",
    color: "#C9A84C",
    letterSpacing: 3,
  },
  tagline: {
    fontSize: 14,
    color: "#888",
    marginTop: 6,
    letterSpacing: 1,
  },
  bottomSpacer: { flex: 1 },
  card: {
    backgroundColor: "#1a1a1a",
    borderRadius: 20,
    padding: 24,
  },
  cardLabel: {
    fontSize: 11,
    color: "#888",
    letterSpacing: 2,
    marginBottom: 8,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: "700",
    color: "#fff",
    marginBottom: 16,
  },
  input: {
    backgroundColor: "#2a2a2a",
    borderRadius: 12,
    paddingVertical: 14,
    color: "#fff",
    fontSize: 24,
    fontWeight: "600",
    letterSpacing: 8,
    marginBottom: 4,
  },
  button: {
    marginTop: 16,
    backgroundColor: "#4CAF50",
    borderRadius: 12,
    paddingVertical: 16,
    alignItems: "center",
  },
  buttonText: { color: "#fff", fontWeight: "700", fontSize: 16 },
  error: { marginTop: 8, color: "#FF6B6B", textAlign: "center" },
  hint: { marginTop: 12, color: "#555", fontSize: 12, textAlign: "center" },
});

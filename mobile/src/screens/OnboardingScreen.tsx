import React, { useState } from "react";
import { View, Text, TextInput, Pressable, StyleSheet, Image } from "react-native";
import { useDispatch } from "react-redux";
import { AppDispatch } from "../state/store";
import { pairWithGateway } from "../state/slices/authSlice";
import { T } from "../theme";

export default function OnboardingScreen() {
  const dispatch = useDispatch<AppDispatch>();
  const [pin, setPin] = useState("1234");
  const [error, setError] = useState<string | null>(null);

  const onPair = async () => {
    setError(null);
    try {
      await dispatch(pairWithGateway(pin)).unwrap();
    } catch {
      setError("Pairing failed. Check your PIN and try again.");
    }
  };

  return (
    <View style={styles.root}>
      {/* spacer pushes hero down so title sits vertically centered */}
      <View style={styles.topSpacer} />

      {/* ── Hero ── */}
      <View style={styles.hero}>
        <Image
          source={require("../assets/logo.png")}
          style={styles.logo}
          resizeMode="contain"
        />
        <Text style={styles.brandName}>BASTIÓN XÓLOT</Text>
        <Text style={styles.brandTagline}>Guardian of Your Network</Text>
      </View>

      <View style={styles.bottomSpacer} />

      {/* ── Pairing Card ── */}
      <View style={styles.card}>
        <Text style={styles.cardEyebrow}>CONNECT TO GATEWAY</Text>
        <Text style={styles.cardTitle}>Enter your pairing PIN</Text>

        <TextInput
          value={pin}
          onChangeText={setPin}
          style={styles.input}
          placeholder="PIN"
          placeholderTextColor={T.textMuted}
          keyboardType="number-pad"
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
    backgroundColor: T.bgBase,
    paddingHorizontal: 24,
    paddingBottom: 40,
  },
  topSpacer: { flex: 1 },
  bottomSpacer: { flex: 1 },
  hero: { alignItems: "center" },
  logo: { width: 300, height: 300 },
  brandName: {
    color: T.gold,
    fontSize: 28,
    fontWeight: "900",
    letterSpacing: 5,
    marginTop: 24,
    textAlign: "center",
  },
  brandTagline: {
    color: T.textSecondary,
    fontSize: 13,
    letterSpacing: 2,
    marginTop: 8,
  },
  card: {
    backgroundColor: T.bgCard,
    borderRadius: 22,
    padding: 24,
    elevation: 12,
    shadowColor: T.gold,
    shadowOffset: { width: 0, height: 6 },
    shadowOpacity: 0.20,
    shadowRadius: 16,
  },
  cardEyebrow: {
    color: T.textMuted,
    fontSize: 11,
    fontWeight: "700",
    letterSpacing: 2,
    marginBottom: 6,
  },
  cardTitle: {
    color: T.textPrimary,
    fontSize: 20,
    fontWeight: "700",
    marginBottom: 20,
  },
  input: {
    backgroundColor: T.bgCardElevated,
    borderRadius: 14,
    paddingHorizontal: 16,
    paddingVertical: 14,
    color: T.textPrimary,
    fontSize: 28,
    fontWeight: "700",
    letterSpacing: 8,
    textAlign: "center",
    borderWidth: 1,
    borderColor: T.borderSubtle,
  },
  button: {
    marginTop: 16,
    backgroundColor: T.jade,
    borderRadius: 14,
    paddingVertical: 16,
    alignItems: "center",
  },
  buttonText: { color: "#000", fontWeight: "800", fontSize: 16 },
  hint: { color: T.textMuted, fontSize: 12, textAlign: "center", marginTop: 12 },
  error: { marginTop: 10, color: T.dangerText, fontSize: 14, textAlign: "center" },
});

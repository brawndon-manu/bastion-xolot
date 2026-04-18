import React, { useState } from "react";
import { View, Text, TextInput, Pressable, StyleSheet } from "react-native";
import { useDispatch } from "react-redux";
import { AppDispatch } from "../state/store";
import { pairWithGateway } from "../state/slices/authSlice";
import { T } from "../theme";

/**
 * Aztec solar disc — concentric rings + radiating spokes.
 * Xolotl guides the sun through the underworld each night;
 * this glyph marks that sacred journey.
 */
function AztecSunDisc() {
  const size = 120;
  const spokeAngles = [0, 45, 90, 135];

  return (
    <View style={{ width: size, height: size, alignItems: "center", justifyContent: "center" }}>
      {/* Radiating spokes */}
      {spokeAngles.map((angle) => (
        <View
          key={angle}
          style={{
            position: "absolute",
            width: 1.5,
            height: size,
            backgroundColor: T.gold,
            opacity: 0.35,
            transform: [{ rotate: `${angle}deg` }],
          }}
        />
      ))}
      {/* Outer ring */}
      <View style={{
        position: "absolute",
        width: size, height: size,
        borderRadius: size / 2,
        borderWidth: 2, borderColor: T.gold, opacity: 0.7,
      }} />
      {/* Middle ring */}
      <View style={{
        position: "absolute",
        width: size * 0.68, height: size * 0.68,
        borderRadius: size * 0.34,
        borderWidth: 1.5, borderColor: T.gold, opacity: 0.55,
      }} />
      {/* Inner ring */}
      <View style={{
        position: "absolute",
        width: size * 0.38, height: size * 0.38,
        borderRadius: size * 0.19,
        borderWidth: 1.5, borderColor: T.gold, opacity: 0.7,
      }} />
      {/* Solar core */}
      <View style={{
        width: size * 0.18, height: size * 0.18,
        borderRadius: size * 0.09,
        backgroundColor: T.gold, opacity: 0.9,
      }} />
    </View>
  );
}

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
      {/* ── Hero ── */}
      <View style={styles.hero}>
        <AztecSunDisc />
        <Text style={styles.brandName}>BASTIÓN XÓLOT</Text>
        <Text style={styles.brandTagline}>Guardian of Your Network</Text>
      </View>

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
    justifyContent: "center",
    paddingHorizontal: 24,
    paddingBottom: 40,
  },
  hero: { alignItems: "center", marginBottom: 52 },
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

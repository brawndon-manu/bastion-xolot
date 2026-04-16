import React, { useState } from "react";
import { View, Text, TextInput, Pressable, StyleSheet } from "react-native";
import { useDispatch } from "react-redux";
import { AppDispatch } from "../state/store";
import { pairWithGateway } from "../state/slices/authSlice";

export default function OnboardingScreen() 
{
  /*
  pin input / error handling
  */
  const dispatch = useDispatch<AppDispatch>();
  const [pin, setPin] = useState("1234");
  const [error, setError] = useState<string | null>(null);

  const onPair = async () => {
    setError(null);

    try {
      await dispatch(pairWithGateway(pin)).unwrap();
    } 
    catch (error) {
      setError("Pairing failed");
    }
  };

  let errorMessage = null;

  if (error)
  {
    errorMessage = <Text style={styles.error}>{error}</Text>
  }
  
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
        {errorMessage}

        <Pressable style={styles.button} onPress={onPair}>
          <Text style={styles.buttonText}>Pair (demo PIN: 1234)</Text>
        </Pressable>

      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 20, backgroundColor: "#c4c4cc", justifyContent: "center" },
  subtitle: { color: "#0c0d0e", fontSize: 16, marginBottom: 18, lineHeight: 22 },
  card: { backgroundColor: "#fff", borderRadius: 16, padding: 16, borderWidth: 1, borderColor: "#fff" },
  label: { color: "#0c0d0e", marginBottom: 8, fontSize: 14 },
  input: { backgroundColor: "#fff", borderRadius: 12, paddingHorizontal: 12, paddingVertical: 10, color: "#070707", borderWidth: 1, borderColor: "#223556" },
  button: { marginTop: 14, backgroundColor: "#2E5BFF", borderRadius: 12, paddingVertical: 12, alignItems: "center" },
  buttonText: { color: "#fff", fontWeight: "700" },
  error: { marginTop: 10, color: "#FF6B6B" },
  hint: { marginTop: 12, color: "#8FA0B5", fontSize: 12, lineHeight: 18 }
});

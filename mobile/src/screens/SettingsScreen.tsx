import React from "react";
import { View, Text, StyleSheet, Pressable, Image, ScrollView } from "react-native";
import { useDispatch } from "react-redux";
import { AppDispatch } from "../state/store";
import { signOut } from "../state/slices/authSlice";
import { CompositeScreenProps } from "@react-navigation/native";
import { BottomTabScreenProps } from "@react-navigation/bottom-tabs";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { T } from "../theme";

type Props = CompositeScreenProps<
  BottomTabScreenProps<import("../App").MainTabParamList, "Settings">,
  NativeStackScreenProps<import("../App").RootStackParamList>
>;

export default function SettingsScreen({ navigation }: Props) {
  const dispatch = useDispatch<AppDispatch>();

  return (
    <ScrollView style={styles.root} contentContainerStyle={styles.content}>
      <Text style={styles.sectionLabel}>ENFORCEMENT</Text>

      <Pressable
        style={[styles.btn, styles.btnControl]}
        onPress={() => navigation.navigate("Controls")}
      >
        <Text style={styles.btnText}>Controls & Enforcement History</Text>
      </Pressable>

      <Text style={styles.sectionLabel}>ACCOUNT</Text>

      <Pressable
        style={[styles.btn, styles.btnSignOut]}
        onPress={() => dispatch(signOut())}
      >
        <Text style={styles.btnText}>Sign Out</Text>
      </Pressable>

      <Image
        source={require("../assets/SUNstoneSettings.png")}
        style={styles.settingsArt}
        resizeMode="contain"
      />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: T.bgBase },
  content: { padding: 16, paddingBottom: 40 },
  sectionLabel: {
    color: T.textGold,
    fontSize: 11,
    fontWeight: "800",
    letterSpacing: 2.5,
    marginTop: 24,
    marginBottom: 10,
  },
  btn: {
    borderRadius: 16,
    paddingVertical: 16,
    paddingHorizontal: 20,
    borderWidth: 1,
  },
  btnControl: {
    backgroundColor: T.bgCard,
    borderColor: T.borderJade,
  },
  btnSignOut: {
    backgroundColor: T.bgCard,
    borderColor: T.borderDanger,
  },
  btnText: {
    color: T.textPrimary,
    fontWeight: "700",
    fontSize: 15,
  },
  settingsArt: {
    width: "100%",
    height: 260,
    marginTop: 24,
  },
});

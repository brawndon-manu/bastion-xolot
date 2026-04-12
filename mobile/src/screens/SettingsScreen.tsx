import React from "react";
import { View, Text, StyleSheet, Pressable } from "react-native";
import { useDispatch } from "react-redux";
import { AppDispatch } from "../state/store";
import { signOut } from "../state/slices/authSlice";
import { CompositeScreenProps } from "@react-navigation/native";
import { BottomTabScreenProps } from "@react-navigation/bottom-tabs";
import { NativeStackScreenProps } from "@react-navigation/native-stack";

type Props = CompositeScreenProps<
  BottomTabScreenProps<import("../App").MainTabParamList, "Settings">,
  NativeStackScreenProps<import("../App").RootStackParamList>
>;

export default function SettingsScreen({ navigation }: Props) 
{
  const dispatch = useDispatch<AppDispatch>();

  return (
    <View style={styles.root}>
      <Pressable style={[styles.btn, styles.btnControl]} onPress={() => navigation.navigate("Controls")}>
        <Text style={styles.btnText}>Controls & Enforcement History</Text>
      </Pressable>

      <Pressable style={[styles.btn, styles.btnSignOut]} onPress={() => dispatch(signOut())}>
        <Text style={styles.btnText}>Sign out</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: "#c4c4cc" },
  btn: { marginTop: 12, borderRadius: 12, paddingVertical: 12, alignItems: "center" },
  btnControl: { backgroundColor: "#2E5BFF" },
  btnSignOut: { backgroundColor: "#FF4D4D" },
  btnText: { color: "#fff", fontWeight: "700" }
});

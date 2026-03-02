import React, { useEffect } from "react";
import { View, Text, FlatList, Pressable, StyleSheet, RefreshControl } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import AlertCard from "../components/AlertCard";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { loadAlerts } from "../state/slices/alertsSlice";
import { CompositeScreenProps } from "@react-navigation/native";
import { BottomTabScreenProps } from "@react-navigation/bottom-tabs";

type Props = CompositeScreenProps<
  BottomTabScreenProps<import("../App").MainTabParamList, "Alerts">,
  NativeStackScreenProps<RootStackParamList>
>;

export default function AlertsScreen({ navigation }: Props) {
  const dispatch = useDispatch<AppDispatch>();
  const { items, loading } = useSelector((s: RootState) => s.alerts);

  useEffect(() => {
    dispatch(loadAlerts());
  }, [dispatch]);

  return (
    <View style={styles.root}>
      <FlatList
        data={items}
        keyExtractor={(a) => a.id}
        refreshControl={<RefreshControl refreshing={loading} onRefresh={() => dispatch(loadAlerts())} />}
        contentContainerStyle={{ gap: 10, paddingBottom: 20 }}
        renderItem={({ item }) => (
          <Pressable onPress={() => navigation.navigate("AlertDetail", { alertId: item.id })}>
            <AlertCard alert={item} />
          </Pressable>
        )}
        ListEmptyComponent={<Text style={styles.empty}>No alerts yet.</Text>}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: "#0B1220" },
  helper: { color: "#B7C0CC", marginBottom: 12 },
  empty: { color: "#8FA0B5", marginTop: 20 }
});

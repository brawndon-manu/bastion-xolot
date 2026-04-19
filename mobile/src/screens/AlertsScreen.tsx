import React, { useEffect } from "react";
import { View, Text, FlatList, Pressable, StyleSheet, RefreshControl } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import AlertCard from "../components/AlertCard";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { loadAlerts, alertUpsert, alertResolved } from "../state/slices/alertsSlice";
import { CompositeScreenProps } from "@react-navigation/native";
import { BottomTabScreenProps } from "@react-navigation/bottom-tabs";
import { api } from "../api/client";
import { T } from "../theme";

type Props = CompositeScreenProps<
  BottomTabScreenProps<import("../App").MainTabParamList, "Alerts">,
  NativeStackScreenProps<RootStackParamList>
>;

export default function AlertsScreen({ navigation }: Props) {
  const dispatch = useDispatch<AppDispatch>();
  const { items, loading, error } = useSelector((state: RootState) => state.alerts);

  useEffect(() => {
    dispatch(loadAlerts());

    api.connectRealtime();
    const unsub = api.subscribe((event) => {
      if (event && event.type === "ALERT_UPSERT")   dispatch(alertUpsert(event.payload));
      if (event && event.type === "ALERT_RESOLVED") dispatch(alertResolved(event.payload));
    });

    return () => { unsub(); };
  }, [dispatch]);

  return (
    <View style={styles.root}>
      {error && <Text style={styles.error}>{error}</Text>}

      <FlatList
        data={items}
        keyExtractor={(alert) => alert.id}
        refreshControl={
          <RefreshControl
            tintColor={T.jade}
            refreshing={loading}
            onRefresh={() => dispatch(loadAlerts())}
          />
        }
        contentContainerStyle={styles.list}
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
  root: { flex: 1, backgroundColor: T.bgBase },
  list: { padding: 16, gap: 10, paddingBottom: 24 },
  empty: { color: T.textSecondary, marginTop: 24, textAlign: "center", letterSpacing: 0.5 },
  error: { color: T.dangerText, margin: 16, marginBottom: 0, fontSize: 13 },
});

import React, { useEffect } from "react";
import { View, Text, FlatList, Pressable, StyleSheet, RefreshControl } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import DeviceCard from "../components/DeviceCard";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { loadDevices } from "../state/slices/devicesSlice";
import { CompositeScreenProps } from "@react-navigation/native";
import { BottomTabScreenProps } from "@react-navigation/bottom-tabs";
import { api } from "../api/client";


/*
screen for viewing all devices on network / refresh and navigaton to details
*/

type Props = CompositeScreenProps<
  BottomTabScreenProps<import("../App").MainTabParamList, "Devices">,
  NativeStackScreenProps<RootStackParamList>
>;

export default function DevicesScreen({ navigation }: Props) 
{
  const dispatch = useDispatch<AppDispatch>();
  const { items, loading } = useSelector((state: RootState) => state.devices);

  useEffect(() => {
    dispatch(loadDevices());
    
    api.connectRealtime();
    const unsub = api.subscribe((event) => {
      if (!event) 
      {
        return;
      }

      if (event.type === "ENFORCEMENT_UPDATED") 
      {
        dispatch(loadDevices());
      }

      if (event.type === "WS_EVENT" && event.event === "event.received") 
      {
        dispatch(loadDevices());
      }
      
    });

    return () => {
      unsub();
    };
  }, [dispatch]);

  return (
    <View style={styles.root}>
      <FlatList
        data={items}
        keyExtractor={(device) => device.id}
        refreshControl={<RefreshControl refreshing={loading} onRefresh={() => dispatch(loadDevices())} />}
        contentContainerStyle={{ gap: 10, paddingBottom: 20 }}
        renderItem={({ item }) => (
          <Pressable onPress={() => navigation.navigate("DeviceDetail", { deviceId: item.id })}>
            <DeviceCard device={item} />
          </Pressable>
        )}
        ListEmptyComponent={<Text style={styles.empty}>No devices yet.</Text>}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: "#c4c4cc" },
  helper: { color: "#B7C0CC", marginBottom: 12 },
  empty: { color: "#0c0d0e", marginTop: 20 }
});

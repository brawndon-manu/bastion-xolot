import React, { useEffect, useMemo, useRef } from "react";
import { View, Text, FlatList, Pressable, StyleSheet, RefreshControl } from "react-native";
import { NativeStackScreenProps } from "@react-navigation/native-stack";
import { RootStackParamList } from "../App";
import DeviceCard from "../components/DeviceCard";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../state/store";
import { deviceSeen, loadDevices } from "../state/slices/devicesSlice";
import { CompositeScreenProps } from "@react-navigation/native";
import { BottomTabScreenProps } from "@react-navigation/bottom-tabs";
import { api, Device, ONLINE_THRESHOLD_MS, parseTimestamp } from "../api/client";
import { T } from "../theme";

const getDeviceTimestamp = (d: any): number => {
  return d.lastSeenMs || parseTimestamp(d.lastSeen) || parseTimestamp(d.last_seen) || 0;
};

function compareIps(a: string, b: string): number {
  const aParts = a.split(".").map(Number);
  const bParts = b.split(".").map(Number);
  for (let i = 0; i < 4; i++) {
    const diff = (aParts[i] ?? 0) - (bParts[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function sortNamedThenIp(devices: Device[], nicknames: Record<string, string>): Device[] {
  const named: Device[] = [];
  const ipOnly: Device[] = [];

  for (const d of devices) {
    if (nicknames[d.id] || d.hostname) {
      named.push(d);
    } else {
      ipOnly.push(d);
    }
  }

  named.sort((a, b) => {
    const nameA = (nicknames[a.id] ?? a.hostname ?? a.ip).toLowerCase();
    const nameB = (nicknames[b.id] ?? b.hostname ?? b.ip).toLowerCase();
    return nameA.localeCompare(nameB);
  });

  ipOnly.sort((a, b) => compareIps(a.ip, b.ip));

  return [...named, ...ipOnly];
}

function sortDevices(
  devices: Device[],
  nicknames: Record<string, string>,
  latestSeenInData: number
): Device[] {
  const online: Device[] = [];
  const offline: Device[] = [];

  for (const d of devices) {
    const ts = getDeviceTimestamp(d);
    const isOnline = latestSeenInData > 0 && latestSeenInData - ts < ONLINE_THRESHOLD_MS;
    if (isOnline) {
      online.push(d);
    } else {
      offline.push(d);
    }
  }

  return [
    ...sortNamedThenIp(online, nicknames),
    ...sortNamedThenIp(offline, nicknames),
  ];
}

function MetricCard({ label, value, accent }: { label: string; value: string; accent: string }) {
  return (
    <View style={[styles.metricCard, { borderTopColor: accent, borderTopWidth: 2 }]}>
      <Text style={[styles.metricValue, { color: accent }]}>{value}</Text>
      <Text style={styles.metricLabel}>{label}</Text>
    </View>
  );
}

/*
 * Screen for viewing all devices on network — refresh and navigation to details.
 */

type Props = CompositeScreenProps<
  BottomTabScreenProps<import("../App").MainTabParamList, "Devices">,
  NativeStackScreenProps<RootStackParamList>
>;

const REFRESH_DEBOUNCE_MS = 60 * 1000;

export default function DevicesScreen({ navigation }: Props) {
  const dispatch = useDispatch<AppDispatch>();
  const { items, loading, nicknames } = useSelector((state: RootState) => state.devices);
  const lastRefresh = useRef<number>(0);

  const latestSeenInData = useMemo(() => {
    const timestamps = items.map(getDeviceTimestamp).filter((t) => t > 0);
    return timestamps.length > 0 ? Math.max(...timestamps) : 0;
  }, [items]);

  const sortedItems = useMemo(() => {
    return sortDevices(items, nicknames, latestSeenInData);
  }, [items, nicknames, latestSeenInData]);

  const onlineCount = useMemo(() => {
    if (latestSeenInData === 0) return 0;
    return items.filter((d) => {
      const ts = getDeviceTimestamp(d);
      return latestSeenInData - ts < ONLINE_THRESHOLD_MS;
    }).length;
  }, [items, latestSeenInData]);

  const offlineCount = useMemo(() => items.length - onlineCount, [items, onlineCount]);

  const throttledRefresh = () => {
    const now = Date.now();
    if (now - lastRefresh.current < REFRESH_DEBOUNCE_MS) return;
    lastRefresh.current = now;
    dispatch(loadDevices());
  };

  useEffect(() => {
    dispatch(loadDevices());
    lastRefresh.current = Date.now();

    api.connectRealtime();
    const unsub = api.subscribe((event) => {
      if (!event) return;
      if (event.type === "ENFORCEMENT_UPDATED") dispatch(loadDevices());
      if (event.type === "DEVICE_SEEN") dispatch(deviceSeen(event.payload));
      if (event.type === "WS_EVENT" && event.event === "event.received") throttledRefresh();
    });

    return () => { unsub(); };
  }, [dispatch]);

  return (
    <View style={styles.root}>
      <View style={styles.metricsRow}>
        <MetricCard label="ONLINE"  value={String(onlineCount)}  accent={T.jadeText} />
        <MetricCard label="OFFLINE" value={String(offlineCount)} accent={T.textSecondary} />
      </View>
      <FlatList
        data={sortedItems}
        keyExtractor={(device) => device.id}
        refreshControl={
          <RefreshControl
            tintColor={T.jade}
            refreshing={loading}
            onRefresh={() => dispatch(loadDevices())}
          />
        }
        contentContainerStyle={styles.list}
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
  root: { flex: 1, backgroundColor: T.bgBase },
  metricsRow: { flexDirection: "row", gap: 10, paddingHorizontal: 16, paddingTop: 16 },
  metricCard: { flex: 1, backgroundColor: T.bgCard, borderRadius: 12, padding: 16, alignItems: "center" },
  metricValue: { fontSize: 36, fontWeight: "700", letterSpacing: -1 },
  metricLabel: { fontSize: 11, color: T.textSecondary, letterSpacing: 1, marginTop: 4 },
  list: { padding: 16, gap: 10, paddingBottom: 24 },
  empty: { color: T.textSecondary, marginTop: 24, textAlign: "center", letterSpacing: 0.5 },
});

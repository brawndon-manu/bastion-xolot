import React, { useEffect } from "react";
import { StatusBar, Text } from "react-native";
import { Provider, useDispatch, useSelector } from "react-redux";
import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import { createBottomTabNavigator } from "@react-navigation/bottom-tabs";
import { store, RootState, AppDispatch } from "./state/store";
import { bootstrapAuth } from "./state/slices/authSlice";
import Icon from "react-native-vector-icons/Feather";

import OnboardingScreen from "./screens/OnboardingScreen";
import DashboardScreen from "./screens/DashboardScreen";
import DevicesScreen from "./screens/DevicesScreen";
import DeviceDetailScreen from "./screens/DeviceDetailScreen";
import AlertsScreen from "./screens/AlertsScreen";
import AlertDetailScreen from "./screens/AlertDetailScreen";
import SettingsScreen from "./screens/SettingsScreen";
import ControlsScreen from "./screens/ControlsScreen";


export type MainTabParamList = {
  Dashboard: undefined;
  Devices: undefined;
  Alerts: undefined;
  Settings: undefined;
};

export type RootStackParamList = {
  Onboarding: undefined;
  MainTabs: undefined;
  DeviceDetail: { deviceId: string };
  AlertDetail: { alertId: string };
  Controls: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();
const Tabs = createBottomTabNavigator<MainTabParamList>();

function TabIcon({ focused, name }: { focused: boolean; name: string }) {
  return (
    <Icon
      name={name}
      size={20}
      color={focused ? "#18E36B" : "#8FA0B5"}
    />
  );
}

function MainTabs() {
  return (
    <Tabs.Navigator
      screenOptions={{
        headerStyle: { backgroundColor: "#0B1220" },
        headerTintColor: "#fff",
        headerTitleAlign: "center",
        tabBarStyle: {
          backgroundColor: "#0B1220",
          borderTopColor: "#1D2B44",
          height: 64,
          paddingBottom: 10,
          paddingTop: 8
        },
        tabBarActiveTintColor: "#18E36B",
        tabBarInactiveTintColor: "#8FA0B5",
        tabBarLabelStyle: { fontSize: 12, fontWeight: "700" }
      }}
    >
      <Tabs.Screen
        name="Dashboard"
        component={DashboardScreen}
        options={{
          title: "Dashboard",
          headerTitle: "Bastión Xólot",
          tabBarLabel: "Dashboard",
          tabBarIcon: ({ focused }) => <TabIcon focused={focused} name="home" />
        }}
      />

      <Tabs.Screen
        name="Devices"
        component={DevicesScreen}
        options={{
          title: "Devices",
          headerTitle: "Devices",
          tabBarLabel: "Devices",
          tabBarIcon: ({ focused }) => <TabIcon focused={focused} name="monitor" />
        }}
      />

      <Tabs.Screen
        name="Alerts"
        component={AlertsScreen}
        options={{
          title: "Alerts",
          headerTitle: "Alerts",
          tabBarLabel: "Alerts",
          tabBarIcon: ({ focused }) => <TabIcon focused={focused} name="alert-triangle" />
        }}
      />

      <Tabs.Screen
        name="Settings"
        component={SettingsScreen}
        options={{
          title: "Settings",
          headerTitle: "Settings",
          tabBarLabel: "Settings",
          tabBarIcon: ({ focused }) => <TabIcon focused={focused} name="settings" />
        }}
      />
    </Tabs.Navigator>
  );
}

function AppInner() {
  const dispatch = useDispatch<AppDispatch>();
  const authed = useSelector((s: RootState) => s.auth.isAuthenticated);

  useEffect(() => {
    dispatch(bootstrapAuth());
  }, [dispatch]);

  return (
    <NavigationContainer>
      <StatusBar barStyle="light-content" />
      <Stack.Navigator
        screenOptions={{
          headerStyle: { backgroundColor: "#0B1220" },
          headerTintColor: "#fff",
          contentStyle: { backgroundColor: "#0B1220" },
          headerTitleAlign: "center"
        }}
      >
        {!authed ? (
          <Stack.Screen name="Onboarding" component={OnboardingScreen} options={{ title: "BASTIÓN XÓLOT" }} />
        ) : (
          <>
            <Stack.Screen name="MainTabs" component={MainTabs} options={{ headerShown: false }} />
            {}
            <Stack.Screen name="DeviceDetail" component={DeviceDetailScreen} options={{ title: "Device" }} />
            <Stack.Screen name="AlertDetail" component={AlertDetailScreen} options={{ title: "Alert Details" }} />
            <Stack.Screen name="Controls" component={ControlsScreen} options={{ title: "Controls" }} />
          </>
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}

export default function App() {
  return (
    <Provider store={store}>
      <AppInner />
    </Provider>
  );
}

import React, { useEffect } from "react";
import { StatusBar, View, Text } from "react-native";
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
import { T } from "./theme";

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

function MainTabs() {
  return (
    <Tabs.Navigator
      screenOptions={{
        headerStyle: { backgroundColor: T.headerBg },
        headerTintColor: T.headerText,
        headerTitleAlign: "center",
        headerShadowVisible: false,
        headerTitleStyle: { fontSize: 17, fontWeight: "600", color: T.headerText },
        tabBarStyle: {
          backgroundColor: T.tabBar,
          borderTopWidth: 0.5,
          borderTopColor: T.borderGold,
          height: 82,
          paddingBottom: 16,
          paddingTop: 8,
        },
        tabBarActiveTintColor: T.tabActive,
        tabBarInactiveTintColor: T.tabInactive,
        tabBarLabelStyle: { fontSize: 10, fontWeight: "600", letterSpacing: 0.3 },
      }}
    >
      <Tabs.Screen
        name="Dashboard"
        component={DashboardScreen}
        options={{
          headerTitle: () => (
            <View style={{ alignItems: "center" }}>
              <Text style={{ fontSize: 15, fontWeight: "900", color: T.gold, letterSpacing: 4 }}>
                BASTIÓN XÓLOT
              </Text>
              <Text style={{ fontSize: 10, color: T.textSecondary, letterSpacing: 2, marginTop: 1 }}>
                SYSTEM DASHBOARD
              </Text>
            </View>
          ),
          tabBarLabel: "Dashboard",
          tabBarIcon: ({ focused, color }) => (
            <Icon name="home" size={22} color={color} />
          ),
        }}
      />

      <Tabs.Screen
        name="Devices"
        component={DevicesScreen}
        options={{
          headerTitle: () => (
            <Text style={{ fontSize: 15, fontWeight: "900", color: T.gold, letterSpacing: 4 }}>
              DEVICES
            </Text>
          ),
          tabBarLabel: "Devices",
          tabBarIcon: ({ focused, color }) => (
            <Icon name="monitor" size={22} color={color} />
          ),
        }}
      />

      <Tabs.Screen
        name="Alerts"
        component={AlertsScreen}
        options={{
          headerTitle: () => (
            <Text style={{ fontSize: 15, fontWeight: "900", color: T.gold, letterSpacing: 4 }}>
              ALERTS
            </Text>
          ),
          tabBarLabel: "Alerts",
          tabBarIcon: ({ focused, color }) => (
            <Icon name="alert-triangle" size={22} color={color} />
          ),
        }}
      />

      <Tabs.Screen
        name="Settings"
        component={SettingsScreen}
        options={{
          headerTitle: () => (
            <Text style={{ fontSize: 15, fontWeight: "900", color: T.gold, letterSpacing: 4 }}>
              SETTINGS
            </Text>
          ),
          tabBarLabel: "Settings",
          tabBarIcon: ({ focused, color }) => (
            <Icon name="settings" size={22} color={color} />
          ),
        }}
      />
    </Tabs.Navigator>
  );
}

function AppInner() {
  const dispatch = useDispatch<AppDispatch>();
  const authed = useSelector((state: RootState) => state.auth.isAuthenticated);

  useEffect(() => { dispatch(bootstrapAuth()); }, [dispatch]);

  const sharedStackOptions = {
    headerStyle: { backgroundColor: T.headerBg },
    headerTitleStyle: { fontSize: 13, fontWeight: "800" as const, color: T.gold, letterSpacing: 2.5 },
    headerTintColor: T.jade,
    contentStyle: { backgroundColor: T.bgBase },
    headerTitleAlign: "center" as const,
    headerShadowVisible: false,
  };

  if (!authed) {
    return (
      <NavigationContainer>
        <StatusBar barStyle="light-content" backgroundColor={T.bgBase} />
        <Stack.Navigator screenOptions={sharedStackOptions}>
          <Stack.Screen
            name="Onboarding"
            component={OnboardingScreen}
            options={{ headerShown: false }}
          />
        </Stack.Navigator>
      </NavigationContainer>
    );
  }

  return (
    <NavigationContainer>
      <StatusBar barStyle="light-content" backgroundColor={T.bgBase} />
      <Stack.Navigator screenOptions={sharedStackOptions}>
        <Stack.Screen name="MainTabs"     component={MainTabs}           options={{ headerShown: false }} />
        <Stack.Screen name="DeviceDetail" component={DeviceDetailScreen} options={{ title: "DEVICE" }} />
        <Stack.Screen name="AlertDetail"  component={AlertDetailScreen}  options={{ title: "ALERT" }} />
        <Stack.Screen name="Controls"     component={ControlsScreen}     options={{ title: "CONTROLS" }} />
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

import React, { useEffect } from "react";
import { StatusBar } from "react-native";
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

/**
 * Main tab navigation shell
 * Resonsible for defining top level authenticated navigation, 
 * assigining icons and labels for each tab, 
 * applying shared tab styling 
*/
function MainTabs() 
{
  return (
    <Tabs.Navigator
      screenOptions={{
        headerStyle: { backgroundColor: "#0c0d0e" },
        headerTintColor: "#fff",
        headerTitleAlign: "center",
        tabBarStyle: { backgroundColor: "#0c0d0e", borderTopColor: "#1D2B44", height: 64, paddingBottom: 10, paddingTop: 8 },
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
          tabBarIcon: ({ focused }) => ( 
          <Icon name = "home" size={20} color={focused ? "#18E36B" : "#8FA0B5"} />
          )}}
      />

      <Tabs.Screen
        name="Devices"
        component={DevicesScreen}
        options={{
          title: "Devices",
          headerTitle: "Devices",
          tabBarLabel: "Devices",
          tabBarIcon: ({ focused }) => (
          <Icon name="monitor" size={20} color={focused ? "#18E36B" : "#8FA0B5"} />
          )}}
      />

      <Tabs.Screen
        name="Alerts"
        component={AlertsScreen}
        options={{
          title: "Alerts",
          headerTitle: "Alerts",
          tabBarLabel: "Alerts",
          tabBarIcon: ({ focused }) => (
          <Icon name="alert-triangle" size={20} color={focused ? "#18E36B" : "#8FA0B5"} />
          )}}
      />

      <Tabs.Screen
        name="Settings"
        component={SettingsScreen}
        options={{
          title: "Settings",
          headerTitle: "Settings",
          tabBarLabel: "Settings",
          tabBarIcon: ({ focused }) => (
          <Icon name="settings" size={20} color={focused ? "#18E36B" : "#8FA0B5"} />
          )}}
      />
    </Tabs.Navigator>
  );
}

function AppInner() 
{
  const dispatch = useDispatch<AppDispatch>();
  const authed = useSelector((state: RootState) => state.auth.isAuthenticated);

  useEffect(() => {
    dispatch(bootstrapAuth());
  }, [dispatch]);

  if (!authed)
  {
    return (
      <NavigationContainer>
        <StatusBar barStyle="light-content" />
        <Stack.Navigator
          screenOptions={{
            headerStyle: { backgroundColor: "#0c0d0e" },
            headerTintColor: "#fff",
            contentStyle: { backgroundColor: "#0c0d0e" },
            headerTitleAlign: "center"
          }}
        >
            <Stack.Screen name="Onboarding" component={OnboardingScreen} options={{ title: "BASTIÓN XÓLOT" }} />
        </Stack.Navigator>
      </NavigationContainer>
    );
  }

  return (
        <NavigationContainer>
      <StatusBar barStyle="light-content" />
      <Stack.Navigator
        screenOptions={{
          headerStyle: { backgroundColor: "#0c0d0e" },
          headerTintColor: "#fff",
          contentStyle: { backgroundColor: "#0c0d0e" },
          headerTitleAlign: "center"
        }}
      >
        <Stack.Screen
          name="MainTabs"
          component={MainTabs}
          options={{ headerShown: false }}
        />
        <Stack.Screen
          name="DeviceDetail"
          component={DeviceDetailScreen}
          options={{ title: "Device" }}
        />
        <Stack.Screen
          name="AlertDetail"
          component={AlertDetailScreen}
          options={{ title: "Alert Details" }}
        />
        <Stack.Screen
          name="Controls"
          component={ControlsScreen}
          options={{ title: "Controls" }}
        />
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

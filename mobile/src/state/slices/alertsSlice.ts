import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import { api, Alert } from "../../api/client";
import type { RootState } from "../store";

type AlertsState = {
  items: Alert[];
  loading: boolean;
  error: string | null;
};

const initialState: AlertsState = {
  items: [],
  loading: false,
  error: null
};

export const loadAlerts = createAsyncThunk("alerts/load", async () => {
  return api.getAlerts();
});

const alertsSlice = createSlice({
  name: "alerts",
  initialState,
  reducers: {
    alertReceived: (s, a) => {
      const alert: Alert = a.payload;
      s.items.unshift(alert);
    }
  },
  extraReducers: (b) => {
    b.addCase(loadAlerts.pending, (s) => {
      s.loading = true;
      s.error = null;
    });
    b.addCase(loadAlerts.fulfilled, (s, a) => {
      s.loading = false;
      s.items = a.payload;
    });
    b.addCase(loadAlerts.rejected, (s, a) => {
      s.loading = false;
      s.error = a.error.message ?? "Failed to load alerts";
    });
  }
});

export const { alertReceived } = alertsSlice.actions;

export const selectAlertById = (state: RootState, id: string) =>
  state.alerts.items.find(a => a.id === id);

export default alertsSlice.reducer;

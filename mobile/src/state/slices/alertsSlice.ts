import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import { api, Alert } from "../../api/client";
import type { RootState } from "../store";

const SEVERITY_RANK: Record<string, number> = { High: 0, Medium: 1, Low: 2 };

function sortAlerts(alerts: Alert[]): Alert[] {
  return [...alerts].sort((a, b) => {
    const aResolved = a.status === "resolved" ? 1 : 0;
    const bResolved = b.status === "resolved" ? 1 : 0;
    if (aResolved !== bResolved) return aResolved - bResolved;
    const sevDiff = (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3);
    if (sevDiff !== 0) return sevDiff;
    return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
  });
}

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
  let alerts = await api.getAlerts();
  return alerts;
});

/**
 * alert
 */

function upsertAlert(items: Alert[], incoming: Alert) {
  const index = items.findIndex((x) => x.id === incoming.id);

  if (index >= 0) {
    items[index] = incoming;
  } else {
    items.unshift(incoming);
  }
}

const alertsSlice = createSlice({
  name: "alerts",
  initialState,
  reducers: {
    alertUpsert: (state, action) => {
      upsertAlert(state.items, action.payload);
      state.items = sortAlerts(state.items);
    },
    alertResolved: (state, action) => {
      upsertAlert(state.items, action.payload);
      state.items = sortAlerts(state.items);
    },
  },
  extraReducers: (builder) => {
    builder.addCase(loadAlerts.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(loadAlerts.fulfilled, (state, action) => {
      state.loading = false;
      state.items = sortAlerts(action.payload);
    });
    builder.addCase(loadAlerts.rejected, (state, action) => {
      state.loading = false;
      state.error = action.error.message || "Failed to load alerts";
    });
  }
});

export const { alertUpsert, alertResolved } = alertsSlice.actions;

export const selectAlertById = (state: RootState, id: string) => {
  return state.alerts.items.find((a) => a.id === id);
};

export default alertsSlice.reducer;
